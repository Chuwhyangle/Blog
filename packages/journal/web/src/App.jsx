import { useEffect, useState } from 'react';
import { StoreProvider, useStore } from './lib/store';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import Setup from './components/Setup';
import { api } from './lib/api';
import './index.css';

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
      <Gate />
    </StoreProvider>
  );
}