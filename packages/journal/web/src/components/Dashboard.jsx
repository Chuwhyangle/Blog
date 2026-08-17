/** 主界面：条目列表 + 编辑器（加密写 / 解密读 / 验签） */
import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api';
import { useStore } from '../lib/store';
import Editor from './Editor';
import RotateReader from './RotateReader';
import {
  decryptEntry, verifyPayload, buildSignaturePayload, b64decode, hexToBytes,
  deriveKEK, verifyKEK,
} from '../lib/crypto';

export default function Dashboard() {
  const { session, clearSession, keys, setKek, signingKeys, signingKey, signingKeyId } = useStore();
  const [entries, setEntries] = useState([]);  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(null);       // 正在编辑的条目（含解密后的明文）
  const [writeKey, setWriteKey] = useState(false);    // 是否需要输主口令（作者写）
  const [rotateOpen, setRotateOpen] = useState(false);
  const [pendingEntry, setPendingEntry] = useState(null);   // 解锁后自动打开的目标条目
  const [pendingNew, setPendingNew] = useState(false);       // 解锁后自动新建编辑器
  const [verificationWarnings, setVerificationWarnings] = useState([]);

  const isOwner = session?.role === 'owner';

  // ── 加载列表 ──
  const loadEntries = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.entries();
      const warnings = [];
      // 逐条验签（⑤ §8：验签不是可选项）
      const verified = [];
      for (const e of list) {
        const pub = signingKeys.find((k) => k.key_id === e.signing_key_id);
        if (!pub) {
          warnings.push(`条目 ${e.id.slice(0, 8)} 的公钥未知，无法验签`);
          verified.push({ ...e, valid: false });
          continue;
        }
        const payload = buildSignaturePayload({
          id: hexToBytes(e.id),
          createdAt: new Date(e.created_at).getTime(),
          updatedAt: new Date(e.updated_at).getTime(),
          visibility: e.visibility,
          ownerEpoch: e.owner_epoch,
          readerEpoch: e.reader_epoch,
          signingKeyId: hexToBytes(e.signing_key_id),
          iv: b64decode(e.iv),
          ciphertext: b64decode(e.ciphertext),
        });
        const ok = await verifyPayload(b64decode(pub.public_key), payload, b64decode(e.signature));
        // 时序检查：条目时间若晚于该公钥退役时间 → 伪造特征（⑩ Q1b）
        const retired = pub.retired_at ? new Date(pub.retired_at).getTime() : Infinity;
        if (new Date(e.created_at).getTime() > retired) {
          warnings.push(`条目 ${e.id.slice(0, 8)} 签名于公钥退役之后（可能被伪造）`);
        }
        verified.push({ ...e, valid: ok });
        if (!ok) warnings.push(`条目 ${e.id.slice(0, 8)} 签名验证失败！`);
      }
      setVerificationWarnings(warnings);
      setEntries(verified);
    } catch (e) {
      console.error('加载失败', e);
      if (e.status === 401) clearSession();
    } finally {
      setLoading(false);
    }
  }, [signingKeys, clearSession]);

  useEffect(() => { loadEntries(); }, [loadEntries]);

  // ── 解密打开编辑器（kekOverride：解锁回调里直接用刚派生的 KEK，避开异步状态）──
  async function openEntry(e, kekOverride) {
    // 访客：reader KEK；本人：owner KEK
    const kek = kekOverride || (isOwner ? keys.owner : keys.reader);
    if (!kek) {
      setPendingEntry(e);
      setWriteKey(true);   // 需要先解锁（输口令派生 KEK）
      return;
    }
    try {
      const plain = await decryptEntry({ ...e, role: isOwner ? 'owner' : 'reader' }, kek);
      setEditing({
        ...e,
        plain,
        signing_key_id_bytes: e.signing_key_id ? hexToBytes(e.signing_key_id) : null,
      });
    } catch (err) {
      // 友好提示：直接展示错误信息（aesGcmDecrypt 已改成中文可读描述）
      alert(err.message || '解密失败');
    }
  }

  // ── 新条目 ──
  function newEntry() {
    if (isOwner && !keys.owner) {
      setPendingNew(true);
      setWriteKey(true);
      return;
    }
    openNew();
  }

  function openNew() {
    if (!signingKey || !signingKeyId) {
      alert('签名密钥未加载，无法写日记');
      return;
    }
    setEditing({
      id: null,
      plain: { title: '', body: '', tags: [] },
      visibility: 'private',
      signing_key_id_bytes: signingKeyId,
    });
  }

  return (
    <div className="dash">
      <header className="dash-head">
        <h1>📔 Journal</h1>
        <div className="right">
          {isOwner && <button className="ghost" onClick={newEntry}>✏️ 新日记</button>}
          {isOwner && <button className="ghost" onClick={() => setRotateOpen(true)}>🔄 轮换读口令</button>}
          <button className="ghost" onClick={loadEntries}>↻ 刷新</button>
          <button className="ghost" onClick={clearSession}>退出</button>
        </div>
      </header>

      {verificationWarnings.length > 0 && (
        <div className="warn-banner">
          {verificationWarnings.map((w, i) => <p key={i}>⚠️ {w}</p>)}
        </div>
      )}

      {writeKey && !isOwner && (
        <UnlockBox mode="reader" onDone={(kek) => {
          setKek('reader', kek); setWriteKey(false);
          // 解锁成功 → 用刚派生的 KEK 直接打开之前想看的条目
          if (pendingEntry) { const t = pendingEntry; setPendingEntry(null); openEntry(t, kek); }
        }} />
      )}
      {writeKey && isOwner && (
        <UnlockBox mode="owner" onDone={(kek) => {
          setKek('owner', kek); setWriteKey(false);
          // 解锁后：要么接着打开条目，要么接着新建编辑器（断点续走）
          if (pendingEntry) { const t = pendingEntry; setPendingEntry(null); openEntry(t, kek); }
          else if (pendingNew) { setPendingNew(false); openNew(); }
        }} />
      )}

      {loading ? (
        <p className="muted">加载中…</p>
      ) : entries.length === 0 ? (
        <p className="muted">还没有日记。{isOwner ? '点击「新日记」开始。' : ''}</p>
      ) : (
        <ul className="entries">
          {entries.map((e) => (
            <li key={e.id} className={`entry ${e.valid ? '' : 'invalid'}`}>
              <button className="entry-main" onClick={() => openEntry(e)}>
                <span className="dot" data-vis={e.visibility} />
                <span className="title">{e.title_hint || e.id.slice(0, 8)}</span>
                <span className="date">{new Date(e.created_at).toLocaleDateString('zh-CN')}</span>
              </button>
              {e.valid === false && <span className="badge">签名无效</span>}
            </li>
          ))}
        </ul>
      )}

      {editing && (
        <Editor
          entry={editing}
          isOwner={isOwner}

          signingKey={signingKey}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); loadEntries(); }}
        />
      )}

      {rotateOpen && (
        <RotateReader
          onClose={() => setRotateOpen(false)}
          onDone={() => {
            setRotateOpen(false);
            loadEntries();
          }}
        />
      )}
    </div>
  );
}

/** 解锁框：输口令 → Argon2id 派生 KEK（内存） */
function UnlockBox({ mode, onDone }) {
  const [pw, setPw] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const { cryptoParams, setKek } = useStore();

  async function go() {
    setBusy(true); setErr('');
    try {
      const params = cryptoParams?.[mode];
      if (!params) throw new Error('服务端未初始化 KDF 参数');
      // 用服务端存的 salt/params 派生（与保存时一致）
      const kek = await deriveKEK(pw, params.salt, params.params);
      // verifier 校验（③ crypto_params）：马上区分「口令错」与后续数据损坏
      const ok = await verifyKEK(params, kek);
      if (!ok) throw new Error('口令错误（verifier 校验未通过）');
      setKek(mode, kek);
      onDone(kek);
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <dialog open className="modal">
      <h3>{mode === 'owner' ? '输入主口令' : '输入读口令'}</h3>
      <p className="hint">{mode === 'owner' ? '解锁私人条目（KEK 只存内存）' : '解锁共享条目'}</p>
      <input type="password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && go()} />
      <button disabled={busy || !pw} onClick={go}>{busy ? '派生中…' : '解锁'}</button>
      {err && <p className="error">{err}</p>}
    </dialog>
  );
}