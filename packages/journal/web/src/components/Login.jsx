/** 登录页：本人（管理员密码）/ 访客（读口令） */
import { useState } from 'react';
import { api } from '../lib/api';
import { useStore } from '../lib/store';

export default function Login({ onAuthed }) {
  const { setSession } = useStore();
  const [tab, setTab] = useState('owner');      // 'owner' | 'reader'
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  // ── 本人：管理员密码登录 ──
  async function adminLogin() {
    setBusy(true); setError('');
    try {
      await api.adminLogin(password);
      setSession({ role: 'owner', can_write: true, credential_label: '管理员' });
      onAuthed();
    } catch (e) {
      setError(e.message || '登录失败');
    } finally {
      setBusy(false);
    }
  }

  // ── 访客读口令登录 ──
  async function readerLogin() {
    setBusy(true); setError('');
    try {
      await api.session(password);
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
            <p className="hint">输入管理员密码登录（主人身份，可写日记）。</p>
            <input
              type="password"
              placeholder="管理员密码"
              value={password}
              autoFocus
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && adminLogin()}
            />
            <button className="primary" disabled={busy || !password} onClick={adminLogin}>
              {busy ? '验证中…' : '🔐 登录'}
            </button>
            <p className="tiny">未初始化？请先完成首次设置（设置管理员密码 + 主口令 + 恢复码）。</p>
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
