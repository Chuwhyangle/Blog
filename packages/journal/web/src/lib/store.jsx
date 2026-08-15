/** 全局状态：会话 / KEK（内存，不落 storage —— ⑤ §4） */
import { createContext, useContext, useEffect, useMemo, useState, useCallback } from 'react';
import { api } from './api';
import { idbGet, KEYS } from './idb';

const StoreCtx = createContext(null);

export function useStore() {
  const ctx = useContext(StoreCtx);
  if (!ctx) throw new Error('useStore must be used within StoreProvider');
  return ctx;
}

export function StoreProvider({ children }) {
  const [session, setSession] = useState(null);        // null | {role, can_write, credential_label}
  const [keys, setKeys] = useState({                    // 内存 KEK（不落 storage）
    owner: null,        // Uint8Array(32)
    reader: null,       // Uint8Array(32)
  });
  const [signingKey, setSigningKey] = useState(null);   // CryptoKey (sign), extractable:false
  const [signingKeyId, setSigningKeyId] = useState(null); // Uint8Array(16) —— 搭配退出/重载清除
  const [cryptoParams, setCryptoParams] = useState(null);
  const [signingKeys, setSigningKeys] = useState([]);   // 服务端公钥列表
  const [loading, setLoading] = useState(true);

  // 启动时恢复会话 + 加载元数据 + 读取本地签名私钥
  useEffect(() => {
    (async () => {
      try {
        const [params, sks, me] = await Promise.all([
          api.cryptoParams(),
          api.signingKeys(),
          api.me(),
        ]);
        setCryptoParams(params);
        setSigningKeys(sks);
        if (me.authenticated) {
          setSession(me);
          // 本人：尝试载入签名密钥（IndexedDB）—— 私钥 + 其 key_id 一起存
          const sk = await idbGet(KEYS.SIGNING_KEY);
          if (sk) {
            setSigningKey(sk.key);
            if (sk.keyId) setSigningKeyId(new Uint8Array(sk.keyId));
          }
        }
      } catch (e) {
        console.warn('初始化失败', e);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const setKek = useCallback((role, kek) => {
    setKeys((k) => ({ ...k, [role]: kek }));
  }, []);

  const clearSession = useCallback(() => {
    setSession(null);
    setKeys({ owner: null, reader: null });
    setSigningKey(null);
    setSigningKeyId(null);
  }, []);

  const value = useMemo(() => ({
    session, setSession,
    keys, setKek,
    signingKey, setSigningKey,
    signingKeyId, setSigningKeyId,
    cryptoParams, setCryptoParams,
    signingKeys, setSigningKeys,
    clearSession,
    loading,
  }), [session, keys, signingKey, signingKeyId, cryptoParams, signingKeys, clearSession, loading, setKek]);

  return <StoreCtx.Provider value={value}>{children}</StoreCtx.Provider>;
}