/**
 * 会话鉴权：httpOnly cookie + HMAC 签名。
 *
 * 相比旧版的改进：
 * - 页面源码不再下发 sha256(password)，前端拿不到任何可重放的凭证；
 * - 兼容模式「哈希即凭证」被彻底移除；
 * - 登录接口只接受 POST body，不再把明文密码放 query。
 *
 * Edge 说明：本文件不使用 node:crypto，改用 Web Crypto（crypto.subtle），
 * 可在 Cloudflare Workers / Next.js edge runtime 运行。会话 token 格式
 * 与旧版完全一致（`<expiresAtMs>.<hmac-hex>`，同一密钥派生），
 * 已签发的旧会话在部署新版后仍可继续校验通过。
 */

export const SESSION_COOKIE = 'ltv_session';
const SESSION_TTL_MS = 90 * 24 * 60 * 60 * 1000; // 90 天

export function getPassword(): string {
  return process.env.PASSWORD || '';
}

export function isPasswordConfigured(): boolean {
  return getPassword().length > 0;
}

const textEncoder = new TextEncoder();

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) return null;
    out[i] = byte;
  }
  return out;
}

/** 恒定时间比较两个字节串（长度不同直接返回 false，不泄露长度外的信息） */
function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function sha256Hex(data: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(data));
  return bytesToHex(new Uint8Array(digest));
}

/**
 * 会话密钥：与旧版 node:crypto 派生结果一致。
 * PROXY_SECRET 优先；否则取 sha256(password + ':libretv::session-salt') 的 hex 串。
 * 不缓存——PASSWORD 在测试中会被临时修改，沿用旧版每次现算的行为。
 */
async function getSecretHex(): Promise<string> {
  if (process.env.PROXY_SECRET) return process.env.PROXY_SECRET;
  return sha256Hex(getPassword() + ':libretv::session-salt');
}

async function getHmacKey(): Promise<CryptoKey> {
  const secret = await getSecretHex();
  return crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

async function hmacHex(payload: string): Promise<string> {
  const key = await getHmacKey();
  const sig = await crypto.subtle.sign('HMAC', key, textEncoder.encode(payload));
  return bytesToHex(new Uint8Array(sig));
}

/** 生成签名会话 token：`<expiresAtMs>.<hmac>` */
export async function signSession(): Promise<{ token: string; expiresAt: number }> {
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const payload = String(expiresAt);
  return { token: `${payload}.${await hmacHex(payload)}`, expiresAt };
}

/** 校验会话 token 的签名与有效期（HMAC 校验用 crypto.subtle.verify，恒定时间） */
export async function verifySession(token: string | undefined | null): Promise<boolean> {
  if (!token) return false;
  const dot = token.lastIndexOf('.');
  if (dot <= 0) return false;
  const payload = token.slice(0, dot);
  const sigBytes = hexToBytes(token.slice(dot + 1));
  if (!sigBytes || sigBytes.length !== 32) return false;
  const key = await getHmacKey();
  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    sigBytes as BufferSource,
    textEncoder.encode(payload)
  );
  if (!valid) return false;
  const expiresAt = parseInt(payload, 10);
  if (!Number.isFinite(expiresAt)) return false;
  return Date.now() < expiresAt;
}

/** 恒定时间比较密码（比较 sha256 摘要避免长度泄漏） */
export async function checkPassword(input: string): Promise<boolean> {
  const password = getPassword();
  if (!password) return false;
  const a = await crypto.subtle.digest('SHA-256', textEncoder.encode(input));
  const b = await crypto.subtle.digest('SHA-256', textEncoder.encode(password));
  return timingSafeEqualBytes(new Uint8Array(a), new Uint8Array(b));
}

/** 从请求 Cookie 中解析会话 */
export async function sessionFromCookieHeader(cookieHeader: string | null): Promise<boolean> {
  if (!cookieHeader) return false;
  const cookies = cookieHeader.split(';');
  for (const c of cookies) {
    const eq = c.indexOf('=');
    if (eq === -1) continue;
    const name = c.slice(0, eq).trim();
    if (name === SESSION_COOKIE) {
      return verifySession(decodeURIComponent(c.slice(eq + 1).trim()));
    }
  }
  return false;
}

// —— 登录速率限制（内存实现，单实例部署足够；多实例可换 Redis） ——

const attemptMap = new Map<string, { count: number; resetAt: number }>();
const MAX_ATTEMPTS = 10;
const WINDOW_MS = 10 * 60 * 1000;

export function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = attemptMap.get(ip);
  if (!entry || now > entry.resetAt) {
    attemptMap.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return true;
  }
  if (entry.count >= MAX_ATTEMPTS) return false;
  entry.count += 1;
  return true;
}

export function clearRateLimit(ip: string): void {
  attemptMap.delete(ip);
}

// 注意：不要在这里加顶层 setInterval 做定期清理——Cloudflare Workers
// 禁止全局作用域的定时器/异步 I/O，模块一被 import 就会 500。
// 过期条目由 checkRateLimit 按 resetAt 惰性替换，Workers 实例生命周期短，
// Map 不会无限膨胀。

