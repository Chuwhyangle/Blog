import { Component, useEffect, useState } from 'react';
import { StoreProvider, useStore } from './lib/store';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import Setup from './components/Setup';
import { api } from './lib/api';
import './index.css';

/** 错误边界：任何渲染/运行时错误显示在页面（不白屏），便于定位 */
class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { err: null };
  }
  static getDerivedStateFromError(err) {
    return { err };
  }
  render() {
    if (this.state.err) {
      return (
        <div style={{ maxWidth: 640, margin: '40px auto', padding: 24, fontFamily: 'monospace', color: '#d64545', background: '#fdecec', border: '1px solid #f0b4b4', borderRadius: 10 }}>
          <h3>页面出错了（错误详情，请发给站长）</h3>
          <p>{String(this.state.err && this.state.err.message)}</p>
          <pre style={{ whiteSpace: 'pre-wrap', fontSize: 12 }}>{String(this.state.err && this.state.err.stack)}</pre>
          <button onClick={() => location.reload()}>刷新重试</button>
        </div>
      );
    }
    return this.props.children;
  }
}

function Gate() {
  const { session, loading } = useStore();
  const [needSetup, setNeedSetup] = useState(false);
  const [forceSetup, setForceSetup] = useState(false);   // 用户手动点「首次设置」

  // 判定是否需要初始化：签名公钥为空 或 KDF 参数为空（不依赖登录态）
  useEffect(() => {
    if (loading) return;
    (async () => {
      try {
        const [keys, params] = await Promise.all([api.signingKeys(), api.cryptoParams()]);
        if (keys.length === 0 || !params?.owner || !params?.reader) setNeedSetup(true);
      } catch {}
    })();
  }, [loading]);

  if (loading) return <div className="boot">加载中…</div>;
  if (needSetup || forceSetup) {
    return <Setup onDone={() => { setNeedSetup(false); setForceSetup(false); }} />;
  }
  if (!session) return <Login onAuthed={() => {}} onSetupClick={() => setForceSetup(true)} />;
  return <Dashboard />;
}

export default function App() {
  return (
    <StoreProvider>
      <ErrorBoundary>
        <Gate />
      </ErrorBoundary>
    </StoreProvider>
  );
}