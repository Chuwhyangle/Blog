// KDF Web Worker（⑪ Q5：Argon2id 必须跑 Worker，不冻结主线程）
// 用 hash-wasm：纯 WASM，无 top-level await，Vite worker 打包无碍。
import { argon2id } from 'hash-wasm';

self.onmessage = async (e) => {
  const { password, saltB64, params } = e.data;
  try {
    // hash-wasm 的 argon2id 需要 Uint8Array salt
    const salt = new Uint8Array(atob(saltB64).split('').map((c) => c.charCodeAt(0)));
    const hash = await argon2id({
      password,
      salt,
      parallelism: params.p,
      iterations: params.t,
      memorySize: params.m,      // KiB
      hashLength: 32,
      outputType: 'hex',
    });
    // 返回 hex，主线程转为 bytes
    self.postMessage({ hashHex: hash });
  } catch (err) {
    self.postMessage({ error: String(err) });
  }
};