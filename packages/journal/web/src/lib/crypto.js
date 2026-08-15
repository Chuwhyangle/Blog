/**
 * 前端加密核心（⑤ 密钥结构 + ⑩ 裁决 Q1b/Q2/Q3）
 *
 * 职责：
 *  - Argon2id 派生 KEK（Web Worker 跑，不冻结主线程 —— ⑪ Q5 强制）
 *  - AES-256-GCM 信封加密（DEK 包给 KEK_owner / KEK_reader / KEK_recovery）
 *  - Ed25519 签名（规范 payload，纯 EdDSA，不先做 SHA-256 —— ⑩ Q3）
 *  - 签名私钥托管（extractable 仅生成瞬间，日常不可导出 —— ⑩ Q1b）
 *
 * 密钥永不离开浏览器（⑤ §4）：
 *  - 口令 / KEK / DEK / 签名私钥一律不发送给服务端
 *  - KEK 只存内存变量，不落 localStorage/sessionStorage
 */

import KdfWorker from './kdf.worker.js?worker';

// ── 常量 ──────────────────────────────────────────────
const AES = 'AES-GCM';
const ED = 'Ed25519';
const SIGNATURE_MAGIC = new TextEncoder().encode('JRNLSIG1');   // 8 字节域分隔

// owner / reader KDF 参数（⑪ Q5：两套参数）
// params 形如 { m: 65536, t: 3, p: 1 }（argon2-browser 用 KiB 语义）
export const KDF_PARAMS = {
  owner: { m: 65536, t: 3, p: 1 },     // ~800ms，自己机器
  reader: { m: 32768, t: 2, p: 1 },    // ~250ms，别人的电脑
  recovery: { m: 32768, t: 2, p: 1 },  // 恢复码熵高（75bit），可再降档
};

// ── 编码工具 ──────────────────────────────────────────
const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64encode(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  }
  return btoa(s);
}
export function b64decode(s) {
  const bin = atob(s);
  const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return b;
}
export function bytesToHex(buf) {
  return [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');
}
export function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return b;
}

// ── Argon2id 派生（Web Worker，不冻结 UI ── ⑪ Q5）──────
// 用 Vite ?worker 导入：无需 importScripts 网络路径，构建期打包 + 内联。
const worker = new KdfWorker();
export function deriveKEK(password, salt, params) {
  return new Promise((resolve, reject) => {
    const onMsg = (e) => {
      worker.removeEventListener('message', onMsg);
      worker.removeEventListener('error', onErr);
      if (e.data.error) reject(new Error(e.data.error));
      else resolve(hexToBytes(e.data.hashHex));
    };
    const onErr = (e) => {
      worker.removeEventListener('message', onMsg);
      worker.removeEventListener('error', onErr);
      reject(e);
    };
    worker.addEventListener('message', onMsg);
    worker.addEventListener('error', onErr);
    const saltB64 = salt instanceof Uint8Array ? b64encode(salt) : salt;
    worker.postMessage({ password, saltB64, params });
  });
}

// ── AES-GCM 信封 ──────────────────────────────────────
function toCryptoKey(keyBytes, usages) {
  return crypto.subtle.importKey('raw', keyBytes, AES, false, usages);
}

export async function aesGcmEncrypt(keyBytes, plaintext, iv) {
  const key = await toCryptoKey(keyBytes, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: AES, iv }, key, plaintext);
  return new Uint8Array(ct);   // 含 GCM tag（16B 尾）
}

async function aesGcmDecrypt(keyBytes, ciphertext, iv) {
  const key = await toCryptoKey(keyBytes, ['decrypt']);
  try {
    const pt = await crypto.subtle.decrypt({ name: AES, iv }, key, ciphertext);
    return new Uint8Array(pt);
  } catch (e) {
    throw new Error('GCM 解密失败（口令错误或数据损坏）');
  }
}

// ── UUIDv7（客户端生成，前 48 位毫秒时间戳 ── ⑩ Q3）────
export function uuidv7Bytes() {
  const now = Date.now();
  const b = new Uint8Array(16);
  // 48 位毫秒时间戳
  b[0] = (now / 2 ** 40) & 0xff;
  b[1] = (now / 2 ** 32) & 0xff;
  b[2] = (now / 2 ** 24) & 0xff;
  b[3] = (now / 2 ** 16) & 0xff;
  b[4] = (now / 2 ** 8) & 0xff;
  b[5] = now & 0xff;
  // 版本与变体
  b[6] = (b[6] & 0x0f) | 0x70;   // version 7
  b[8] = (b[8] & 0x3f) | 0x80;   // variant 10xx
  crypto.getRandomValues(b.subarray(6, 16));   // 剩余 62 bit 随机
  b[7] = (b[7] & 0x0f) | 0x70;
  return b;
}

// ── 签名 payload（⑩ Q3 规范化编码：77B 固定头 + 变长尾）─
export function buildSignaturePayload({ id, createdAt, updatedAt, visibility, ownerEpoch, readerEpoch, signingKeyId, iv, ciphertext }) {
  const parts = [];
  parts.push(SIGNATURE_MAGIC);                                   // 0..8
  parts.push(id);                                                // 8..24 UUIDv7
  // 毫秒时间戳 int64 BE
  const ms = (msValue) => {
    const b = new Uint8Array(8);
    const dv = new DataView(b.buffer);
    dv.setBigUint64(0, BigInt(msValue));
    return b;
  };
  parts.push(ms(createdAt));                                     // 24..32
  parts.push(ms(updatedAt));                                     // 32..40
  parts.push(new Uint8Array([visibility === 'shared' ? 1 : 0])); // 40..41
  const u32 = (v) => {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v);
    return b;
  };
  parts.push(u32(ownerEpoch));                                   // 41..45
  parts.push(u32(readerEpoch));                                  // 45..49
  parts.push(signingKeyId);                                      // 49..65
  parts.push(iv);                                                // 65..77
  parts.push(ciphertext);                                        // 77..（变长尾）

  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// ── Ed25519 签名 / 验签 ───────────────────────────────
export async function signPayload(privateKey, payload) {
  return new Uint8Array(await crypto.subtle.sign(ED, privateKey, payload));
}

export async function verifyPayload(publicKeyBytes, payload, signature) {
  const key = await crypto.subtle.importKey('raw', publicKeyBytes, { name: ED }, false, ['verify']);
  return crypto.subtle.verify(ED, key, signature, payload);
}

// ── 签名密钥对生成 + 托管（⑩ Q1b）──────────────────────
export async function generateSigningKeyPair() {
  // 生成时 extractable=true（仅此瞬间，用于导出托管）
  const kp = await crypto.subtle.generateKey({ name: ED }, true, ['sign', 'verify']);
  const raw = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
  // 重新导入不可导出的日常副本
  const daily = await crypto.subtle.importKey('pkcs8', raw, { name: ED }, false, ['sign']);
  const verifyKey = await crypto.subtle.importKey('spki', await crypto.subtle.exportKey('spki', kp.publicKey), { name: ED }, false, ['verify']);
  return { privateKey: daily, publicKey: verifyKey, rawPrivatePkcs8: new Uint8Array(raw) };
}

// ── 主流程：信封加密一条日记 ────────────────────────────
export async function encryptEntry({
  title, body, tags,
  visibility,             // 'private' | 'shared'
  keks,                   // { owner: bytes|CryptoKey, reader?: bytes|CryptoKey }
  ownerEpoch, readerEpoch,
  signingKey,             // CryptoKey (sign)
  signingKeyId,           // Uint8Array(16)
}) {
  // 1. 每次保存都换新 DEK + IV（⑪ 补充缺口①）
  const dek = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = enc.encode(JSON.stringify({ title, body, tags }));

  const now = Date.now();
  const id = uuidv7Bytes();

  // 2. 正文加密
  const ciphertext = await aesGcmEncrypt(dek, plaintext, iv);

  // 3. 封套
  const dekOwnerIv = crypto.getRandomValues(new Uint8Array(12));
  const dekOwner = await aesGcmEncrypt(keks.owner, dek, dekOwnerIv);
  let dekReader = null, dekReaderIv = null;
  if (visibility === 'shared' && keks.reader) {
    dekReaderIv = crypto.getRandomValues(new Uint8Array(12));
    dekReader = await aesGcmEncrypt(keks.reader, dek, dekReaderIv);
  }

  // 4. 签名（覆盖 id/时间/可见性/epoch/iv/ciphertext —— ⑩ Q3）
  const payload = buildSignaturePayload({
    id, createdAt: now, updatedAt: now,
    visibility, ownerEpoch, readerEpoch,
    signingKeyId, iv, ciphertext,
  });
  const signature = await signPayload(signingKey, payload);

  return {
    id: bytesToHex(id),
    visibility,
    created_at: new Date(now).toISOString(),
    updated_at: new Date(now).toISOString(),
    ciphertext: b64encode(ciphertext),
    iv: b64encode(iv),
    dek_owner: b64encode(dekOwner),
    dek_owner_iv: b64encode(dekOwnerIv),
    dek_reader: dekReader ? b64encode(dekReader) : null,
    dek_reader_iv: dekReaderIv ? b64encode(dekReaderIv) : null,
    signature: b64encode(signature),
    signing_key_id: bytesToHex(signingKeyId),
    owner_epoch: ownerEpoch,
    reader_epoch: visibility === 'shared' ? readerEpoch : 0,
  };
}

// ── 主流程：解密一条（作者用 KEK_owner，访客用 KEK_reader）──────
export async function decryptEntry(entry, kek) {
  const ciphertext = b64decode(entry.ciphertext);
  const iv = b64decode(entry.iv);
  // 作者：dek 由 dek_owner 解出；访客：dek 由 dek_reader 解出
  const wrapped = entry.role === 'reader' ? entry.dek_reader : entry.dek_owner;
  const wrappedIv = entry.role === 'reader' ? entry.dek_reader_iv : entry.dek_owner_iv;
  if (!wrapped || !wrappedIv) throw new Error('该条目没有对应的封套');

  const dek = await aesGcmDecrypt(kek, b64decode(wrapped), b64decode(wrappedIv));
  const plaintext = await aesGcmDecrypt(dek, ciphertext, iv);
  return JSON.parse(dec.decode(plaintext));   // { title, body, tags }
}

// ── 轮换重包：用新 KEK 重包 DEK（⑤ §7 读口令轮换）───────────────
export async function rewrapDEK(entry, oldKek, newKek) {
  const wrapped = entry.role === 'reader' ? entry.dek_reader : entry.dek_owner;
  const wrappedIv = entry.role === 'reader' ? entry.dek_reader_iv : entry.dek_owner_iv;
  const dek = await aesGcmDecrypt(oldKek, b64decode(wrapped), b64decode(wrappedIv));
  const newIv = crypto.getRandomValues(new Uint8Array(12));
  const newWrapped = await aesGcmEncrypt(newKek, dek, newIv);
  return { wrapped: b64encode(newWrapped), iv: b64encode(newIv) };
}