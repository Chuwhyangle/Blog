/** 登录页：本人（WebAuthn passkey）/ 访客（读口令） */
import { useState } from 'react';
import { api } from '../lib/api';
import { useStore } from '../lib/store';

export default function Login({ onAuthed }) {
  const { setSession, setSigningKey, setKek } = useStore();
  const [tab, setTab] = useState('owner');      // 'owner' | 'reader'
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  // ── 本人 passkey 登录 ──
  async function passkeyLogin() {
    setBusy(true); setError('');
    try {
      const opts = await api.webauthnLoginOptions();
      const cred = await navigator.credentials.get({
        publicKey: {
          challenge: base64urlToBytes(opts.challenge),
          rpId: opts.rp_id,
          userVerification: 'required',
          timeout: 120000,
        },
      });
      const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const body = {
        credential: {
          id: cred.id,
          rawId: b64url(cred.rawId),
          type: cred.type,
          response: {
            clientDataJSON: b64url(cred.response.clientDataJSON),
            authenticatorData: b64url(cred.response.authenticatorData),
            signature: b64url(cred.response.signature),
            userHandle: cred.response.userHandle ? b64url(cred.response.userHandle) : null,
          },
          challenge: b64url(opts.challenge),
        },
      };
      const res = await api.webauthnLoginVerify(body);
      setSession({ role: 'owner', can_write: res.can_write, credential_label: res.label });
      onAuthed();
    } catch (e) {
      setError(e.message || 'passkey 登录失败');
    } finally {
      setBusy(false);
    }
  }

  // ── 访客读口令登录 ──
  async function readerLogin() {
    setBusy(true); setError('');
    try {
      const res = await api.session(password);
      setSession({ role: 'reader', can_write: false, credential_label: '访客' });
      onAuthed();
    } catch (e) {
      setError(e.message || '口令错误');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <div className="login-card">
        <h1>📔 Journal</h1>
        <p className="sub">私人加密日记</p>

        <div className="tabs">
          <button className={tab === 'owner' ? 'active' : ''} onClick={() => setTab('owner')}>本人</button>
          <button className={tab === 'reader' ? 'active' : ''} onClick={() => setTab('reader')}>访客</button>
        </div>

        {tab === 'owner' ? (
          <div className="login-body">
            <p className="hint">使用设备上的 Windows Hello / 触控 ID 验证身份。</p>
            <button className="primary" disabled={busy} onClick={passkeyLogin}>
              {busy ? '验证中…' : '🔐 用 Passkey 登录'}
            </button>
            <p className="tiny">未初始化？请先完成首次设置（注册 passkey + 主口令 + 恢复码）。</p>
          </div>
        ) : (
          <div className="login-body">
            <input
              type="password"
              placeholder="访客读口令"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && readerLogin()}
            />
            <button className="primary" disabled={busy || !password} onClick={readerLogin}>
              {busy ? '验证中…' : '进入'}
            </button>
          </div>
        )}

        {error && <p className="error">{error}</p>}
      </div>
    </div>
  );
}

function base64urlToBytes(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return b;
}