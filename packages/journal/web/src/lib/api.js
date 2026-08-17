/** API 客户端：所有请求自动带 cookie（__Host-sid） */
const BASE = '/api';

async function request(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(BASE + path, opts);
  if (res.status === 401) {
    // 会话过期——由调用方处理跳登录
    const err = new Error('未登录');
    err.status = 401;
    throw err;
  }
  if (res.status === 429) {
    const err = new Error('尝试过于频繁，请稍后再试');
    err.status = 429;
    throw err;
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const j = await res.json();
      detail = j.detail || JSON.stringify(j);
    } catch {}
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export const api = {
  // 会话
  me: () => request('GET', '/me'),
  session: (password) => request('POST', '/session', { password }),
  adminLogin: (password) => request('POST', '/admin/login', { password }),
  setupAdminPassword: (password) => request('POST', '/setup/admin-password', { password }),
  setupStatus: () => request('GET', '/setup/status'),
  logout: () => request('POST', '/logout'),

  // WebAuthn
  webauthnRegisterOptions: (canWrite) =>
    request('POST', `/webauthn/register/options${canWrite ? '?can_write=1' : ''}`),
  webauthnRegisterVerify: (body) => request('POST', '/webauthn/register/verify', body),
  webauthnLoginOptions: () => request('POST', '/webauthn/login/options'),
  webauthnLoginVerify: (body) => request('POST', '/webauthn/login/verify', body),

  // 条目
  entries: () => request('GET', '/entries'),
  createEntry: (entry) => request('POST', '/entries', entry),
  updateEntry: (id, entry) => request('PUT', `/entries/${id}`, entry),
  deleteEntry: (id) => request('DELETE', `/entries/${id}`),

  // 元数据
  cryptoParams: () => request('GET', '/crypto/params'),
  signingKeys: () => request('GET', '/signing-keys'),
  escrow: () => request('GET', '/auth/recover/escrow'),

  // 恢复
  recover: (code) => request('POST', '/auth/recover', { code }),
  rotateRecovery: () => request('POST', '/auth/recover/rotate'),
  uploadEscrow: (body) => request('PUT', '/auth/recover/escrow', body),

  // 凭据管理
  credentials: () => request('GET', '/credentials'),
  deleteCredential: (id) => request('DELETE', `/credentials/${id}`),
};