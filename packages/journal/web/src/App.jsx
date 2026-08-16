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

  // 判定是否需要初始化（服务端无任何凭据/公钥时）
  useEffect(() => {
    if (loading || !session) return;
    (async () => {
      try {
        const keys = await api.signingKeys();
        if (keys.length === 0) setNeedSetup(true);
      } catch {}
    })();
  }, [loading, session]);

  if (loading) return <div className="boot">加载中…</div>;
  if (!session) return <Login onAuthed={() => {}} />;
  if (needSetup) return <Setup onDone={() => setNeedSetup(false)} />;
  return <Dashboard />;
}

export default function App() {
  return (
    <StoreProvider>
      <Gate />
    </StoreProvider>
  );
}