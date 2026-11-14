/**
 * SSRF 防护。
 *
 * Edge 说明：本文件不使用 node:dns / node:async_hooks / undici，
 * 可在 Cloudflare Workers / Next.js edge runtime 运行。
 * - DNS 解析改用 DNS-over-HTTPS（Cloudflare DoH JSON API）；
 * - 连接级 undici Agent 改为原生 fetch + 预检；
 * - AsyncLocalStorage 改为模块级上下文栈（见 runWithSSRFProtection）。
 *
 * 已知局限（相对旧版 undici 连接级防护）：原生 fetch 自行解析 DNS，
 * 预检（DoH）与实际建连之间存在理论上的 TOCTOU / DNS Rebinding 窗口——
 * 域名可能在预检后、建连前被改解析到内网地址。edge 环境没有自定义
 * 连接/DNS 的能力，DoH 预检是目前能做到的最好防护，因此它属于
 * best-effort，不能替代连接级校验。不要因此移除本文件的任何校验。
 */

/**
 * 在安装 fetch 包装器之前先捕获原始 fetch，供 DoH 查询使用，
 * 避免 DoH 请求走包装器导致无限递归。
 */
const nativeFetch: typeof fetch | null =
  typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null;

/** 去掉 URL.hostname 对 IPv6 附加的方括号（"[::1]" → "::1"） */
function stripBrackets(host: string): string {
  return host.trim().replace(/^\[+|\]+$/g, '');
}

/**
 * IPv4-mapped / IPv4-compatible IPv6 还原为点分十进制，命中不到时返回 null。
 * "::ffff:192.168.1.100" 与 "::ffff:c0a8:164" 都会归一化成 "192.168.1.100"，
 * 否则这类地址会绕过下面的私网规则被当成公网放行。
 */
function toIPv4(ip: string): string | null {
  const v = ip.replace(/^0:0:0:0:0:/i, '::'); // 全写形式
  const dotted = /^::(?:ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(v);
  if (dotted) return dotted[1];
  const hex = /^::(?:ffff:)?([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(v);
  if (!hex) return null;
  const n = (((parseInt(hex[1], 16) << 16) | parseInt(hex[2], 16)) >>> 0);
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** 判断 IP 是否为私有/回环/链路本地/保留地址（SSRF 防护） */
export function isPrivateIP(ip: string): boolean {
  let v = stripBrackets(ip.trim());
  v = toIPv4(v) ?? v;
  if (/^(127\.|0\.0\.0\.0$|::1$|::$|fe80:|fc|fd)/i.test(v)) return true;
  if (v.startsWith('10.')) return true;
  if (v.startsWith('192.168.')) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(v)) return true;
  if (v.startsWith('169.254.')) return true; // 链路本地（含云元数据 169.254.169.254）
  if (v.startsWith('100.64.')) return true; // CGNAT
  if (v.startsWith('192.0.0.')) return true; // 协议分配块
  return false;
}

const BLOCKED_HOSTNAMES = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1']);

/** URL 字面量校验：协议白名单 + 主机名/字面量 IP 黑名单 */
export function isValidProxyUrl(urlString: string): boolean {
  try {
    const parsed = new URL(urlString);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
    const host = stripBrackets(parsed.hostname); // "[::1]" 也要能被黑名单命中
    if (BLOCKED_HOSTNAMES.has(host)) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) {
      if (isPrivateIP(host)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

interface DohAnswer {
  data: string;
  type: number;
}

interface DohResponse {
  Answer?: DohAnswer[];
  Status?: number;
}

const DOH_URL = 'https://cloudflare-dns.com/dns-query';

// DNS 解析结果缓存：同一主机名在 TTL 内只查一次 DoH。
// 搜索一次要对每个源做多次校验（显式预检 + 每次 fetch 的包装器校验），
// 不缓存时同一主机名会重复查 A/AAAA，子请求数会撑爆 Workers 单次调用 50 上限。
// Workers 实例生命周期短，5 分钟 TTL 足够且不会长期持有过期解析。
const DNS_CACHE_TTL_MS = 5 * 60 * 1000;
const dnsCache = new Map<string, { addresses: string[]; expiresAt: number }>();

/**
 * 用 DNS-over-HTTPS 解析主机名，返回全部解析到的 IP 地址（A + AAAA）。
 * 查询走安装包装器之前捕获的原始 fetch，不经过 SSRF 包装器，避免递归。
 * 单个类型查询失败不阻断，返回已拿到的地址（可能为空）。
 */
async function dohLookup(hostname: string): Promise<string[]> {
  const now = Date.now();
  const cached = dnsCache.get(hostname);
  if (cached && now < cached.expiresAt) return cached.addresses;
  if (!nativeFetch) return [];
  const addresses: string[] = [];
  const results = await Promise.all(
    (['A', 'AAAA'] as const).map(async (type) => {
      try {
        const res = await nativeFetch(
          `${DOH_URL}?name=${encodeURIComponent(hostname)}&type=${type}`,
          {
            headers: { Accept: 'application/dns-json' },
            signal: AbortSignal.timeout(5000),
          }
        );
        if (!res.ok) return;
        const json = (await res.json()) as DohResponse;
        for (const ans of json.Answer ?? []) {
          if (typeof ans.data === 'string') addresses.push(stripBrackets(ans.data));
        }
      } catch {
        // 单个类型查询失败不阻断，继续下一个类型
      }
    })
  );
  void results;
  dnsCache.set(hostname, { addresses, expiresAt: Date.now() + DNS_CACHE_TTL_MS });
  return addresses;
}

/** DNS 解析后校验目标主机名是否解析到内网/保留地址 */
export async function isBlockedByDNS(urlString: string): Promise<boolean> {
  try {
    const hostname = stripBrackets(new URL(urlString).hostname);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':')) {
      return isPrivateIP(hostname);
    }
    const addresses = await dohLookup(hostname);
    return addresses.some((addr) => isPrivateIP(addr));
  } catch {
    return false; // 解析失败不阻断，交给后续请求处理
  }
}

export type UpstreamVerdict = { ok: true } | { ok: false; reason: string };

/**
 * 出网请求的统一校验入口：字面量校验 + DNS 解析校验。
 *
 * 任何由用户输入驱动的服务端请求（采集站搜索/详情、代理转发）都必须先过这一关，
 * 否则服务器会变成内网探测跳板（/api/search 曾直接用用户传的 source.url 发请求）。
 */
export async function checkUpstreamAllowed(urlString: string): Promise<UpstreamVerdict> {
  if (!isValidProxyUrl(urlString)) {
    return { ok: false, reason: '目标地址不在允许范围内（仅支持公网 http/https）' };
  }
  if (await isBlockedByDNS(urlString)) {
    return { ok: false, reason: '目标地址解析到私有/保留网络' };
  }
  return { ok: true };
}

/** 直播场景是否放行内网地址（自建 IPTV）；由部署者显式开启 */
export function allowLivePrivate(): boolean {
  return process.env.LIVE_ALLOW_PRIVATE === '1';
}

/**
 * 直播地址专用校验：协议必须 http(s)，默认仍拒绝内网，但部署者可用
 * LIVE_ALLOW_PRIVATE=1 显式放行（自建 IPTV 常位于内网）。
 *
 * 与点播侧 checkUpstreamAllowed 的区别只在这一处开关：
 * 订阅/播放列表若沿用点播那把尺子，会静默过滤掉内网自建源。
 */
export async function checkLiveUrlAllowed(urlString: string): Promise<UpstreamVerdict> {
  try {
    const parsed = new URL(urlString);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { ok: false, reason: '直播地址仅支持 http/https 协议' };
    }
  } catch {
    return { ok: false, reason: '无效的直播地址' };
  }
  if (allowLivePrivate()) return { ok: true };
  return checkUpstreamAllowed(urlString);
}


export interface SSRFProtectionContext {
  active: boolean;
  allowPrivate?: boolean;
}

/**
 * 防护上下文栈（替代旧版 node:async_hooks 的 AsyncLocalStorage，edge 没有该 API）。
 *
 * runWithSSRFProtection 入栈、结束时出栈；fetch 包装器按栈顶上下文决定是否校验。
 * 并发说明：单 isolate 内多请求交错时，栈顶可能属于另一个并发请求，
 * 因此 currentSSRFContext 取「最严格的活动上下文」（任一活动上下文要求
 * allowPrivate=false 即按严格处理）——只会多校验（安全方向），不会漏校验。
 */
const ssrfContextStack: SSRFProtectionContext[] = [];

function currentSSRFContext(): SSRFProtectionContext | undefined {
  if (ssrfContextStack.length === 0) return undefined;
  for (let i = ssrfContextStack.length - 1; i >= 0; i--) {
    if (!ssrfContextStack[i].allowPrivate) return ssrfContextStack[i];
  }
  return ssrfContextStack[ssrfContextStack.length - 1];
}

const GLOBAL_FETCH_WRAPPED = Symbol.for('libretv.ssrf.fetch.wrapped');

/** 抛给调用方的 SSRF 拦截错误（cause.code 与旧版 undici 守卫一致，供 fetch-utils 归一化） */
function ssrfBlockedError(reason: string): Error {
  const message = `目标地址被拒绝: ${reason}`;
  return Object.assign(new Error(message), {
    cause: { code: 'ERR_SSRF_BLOCKED', message: reason },
  });
}

/** allowPrivate 作用域内的校验：只要求 http(s) 协议，内网地址由调用方显式放行 */
function checkPrivateAllowedUrl(urlString: string): UpstreamVerdict {
  try {
    const parsed = new URL(urlString);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { ok: false, reason: '直播地址仅支持 http/https 协议' };
    }
  } catch {
    return { ok: false, reason: '无效的直播地址' };
  }
  return { ok: true };
}

/**
 * 安装安全的 fetch SSRF 防护包装器。
 * 受保护作用域内（runWithSSRFProtection）的每次 fetch 都先过显式校验
 *（字面量 + DoH DNS），通过后才用原生 fetch 发请求；作用域外不干预。
 * 不再使用 undici Agent——edge 环境没有自定义连接/DNS 的能力。
 *
 * 注意：allowPrivate 取自 runWithSSRFProtection 的调用方上下文（与旧版
 * undici Agent 的行为一致），而不是 LIVE_ALLOW_PRIVATE 环境变量——
 * 后者是 checkLiveUrlAllowed 的部署级开关，只用于 fetch-utils 的显式预检。
 */
export function installFetchSSRFProtection(): void {
  const g = globalThis as unknown as Record<symbol, boolean>;
  if (g[GLOBAL_FETCH_WRAPPED]) return;
  g[GLOBAL_FETCH_WRAPPED] = true;

  const originalFetch = globalThis.fetch;

  globalThis.fetch = async function ssrfProtectedFetch(
    input: RequestInfo | URL,
    init?: RequestInit
  ): Promise<Response> {
    const ctx = currentSSRFContext();
    if (!ctx || !ctx.active) {
      return originalFetch(input, init);
    }

    let urlString: string;
    try {
      urlString = input instanceof Request ? input.url : String(input);
    } catch {
      return originalFetch(input, init);
    }

    const verdict = ctx.allowPrivate
      ? checkPrivateAllowedUrl(urlString)
      : await checkUpstreamAllowed(urlString);
    if (!verdict.ok) throw ssrfBlockedError(verdict.reason);
    return originalFetch(input, init);
  };
}

// 兼容别名
export const installConnectionSSRFProtection = installFetchSSRFProtection;

// 模块加载时自动安装防护
installFetchSSRFProtection();

/**
 * 在受 SSRF 防护的作用域中执行异步请求。
 *
 * 注意：相对旧版的连接级防护（undici Agent 在建连时校验），本实现是
 * 预检 + 原生 fetch，存在理论上的 TOCTOU / DNS Rebinding 窗口（见文件头注释）。
 * 但每一跳仍会重新校验（fetch-utils 的手动重定向逐跳校验），且字面量私网
 * 地址与黑名单主机名在任何情况下都会被拦截。
 */
export function runWithSSRFProtection<T>(
  options: { allowPrivate?: boolean } = {},
  fn: () => Promise<T>
): Promise<T> {
  const ctx: SSRFProtectionContext = { active: true, allowPrivate: options.allowPrivate };
  ssrfContextStack.push(ctx);
  const remove = () => {
    const idx = ssrfContextStack.indexOf(ctx);
    if (idx !== -1) ssrfContextStack.splice(idx, 1);
  };
  let result: Promise<T>;
  try {
    result = fn();
  } catch (err) {
    remove();
    throw err;
  }
  return result.finally(remove);
}
