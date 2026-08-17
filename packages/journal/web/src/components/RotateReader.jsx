/** 读口令轮换（⑤ §7 + ⑩ key_epoch）：
 *  1. 输入新读口令 → 派生新 KEK_reader'（随机新 salt）
 *  2. 逐条 shared 条目：旧 KEK 解 DEK → 新 KEK 重包 + reader_epoch+1 + 重新签名（同签名钥）
 *  3. 全部成功后 PUT /api/crypto/rotate-reader 落库（password_hash/salt/verifier/epoch+1）
 *  可断点续跑：已重包的条目标记 epoch+1，重入时再加 1，无害。
 */
import { useState } from 'react';
import { api } from '../lib/api';
import { useStore } from '../lib/store';
import {
  deriveKEK, KDF_PARAMS, rewrapDEK, buildSignaturePayload, signPayload,
  aesGcmEncrypt, b64decode, b64encode, hexToBytes,
} from '../lib/crypto';

export default function RotateReader({ onClose, onDone }) {
  const { keys, setKek, cryptoParams, setCryptoParams, signingKey } = useStore();
  const [newPw, setNewPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [progress, setProgress] = useState('');

  const oldKek = keys.reader;

  async function go() {
    setBusy(true); setErr(''); setProgress('');
    try {
      if (newPw.length < 8) throw new Error('新读口令至少 8 位');
      if (!oldKek) throw new Error('请先解锁旧读口令（KEK 不在内存）');
      if (!signingKey) throw new Error('签名密钥未加载，无法重新签名');
      // 需要新 salt 才能派生一致的密钥（不能用旧 salt —— 会覆盖派生路径）
      const newSalt = crypto.getRandomValues(new Uint8Array(32));
      const newKek = await deriveKEK(newPw, newSalt, KDF_PARAMS.reader);

      const list = await api.entries();
      const shareds = list.filter((e) => e.visibility === 'shared');
      let done = 0;
      for (const e of shareds) {
        const rewrapped = await rewrapDEK({ ...e, role: 'reader' }, oldKek, newKek);
        const readerEpoch = (e.reader_epoch || 0) + 1;
        // dek_* 不在签名覆盖范围内，但 epoch 在 —— 必须重新签名
        const payload = buildSignaturePayload({
          id: hexToBytes(e.id),
          createdAt: new Date(e.created_at).getTime(),
          updatedAt: new Date(e.updated_at).getTime(),
          visibility: e.visibility,
          ownerEpoch: e.owner_epoch,
          readerEpoch,
          signingKeyId: hexToBytes(e.signing_key_id),
          iv: b64decode(e.iv),
          ciphertext: b64decode(e.ciphertext),
        });
        const sig = await signPayload(signingKey, payload);
        await api.updateEntry(e.id, {
          id: e.id,
          visibility: e.visibility,
          created_at: e.created_at,
          updated_at: e.updated_at,
          ciphertext: e.ciphertext,
          iv: e.iv,
          dek_owner: e.dek_owner,
          dek_owner_iv: e.dek_owner_iv,
          dek_reader: rewrapped.wrapped,
          dek_reader_iv: rewrapped.iv,
          signature: b64encode(sig),
          signing_key_id: e.signing_key_id,
          owner_epoch: e.owner_epoch,
          reader_epoch: readerEpoch,
        });
        done += 1;
        setProgress(`重包 ${done}/${shareds.length}`);
      }

      // verifier：AES-GCM('journal-verifier-v1', KEK_reader')
      const fixed = new TextEncoder().encode('journal-verifier-v1');
      const vIv = crypto.getRandomValues(new Uint8Array(12));
      const verifier = await aesGcmEncrypt(newKek, fixed, vIv);

      await api.rotateReaderPassword({
        password: newPw,
        salt: b64encode(newSalt),
        params: KDF_PARAMS.reader,
        verifier: b64encode(verifier),
        verifier_iv: b64encode(vIv),
      });

      setKek('reader', newKek);
      setCryptoParams(await api.cryptoParams());
      setProgress('完成');
      onDone();
    } catch (ex) {
      setErr(ex.message || '轮换失败');
    } finally {
      setBusy(false);
    }
  }

  return (
    <dialog open className="modal">
      <h3>🔄 轮换读口令</h3>
      <p className="hint">所有 shared 条目会用新读口令重新封装（DEK 不变，封套换新）。期间请勿关闭页面。</p>
      <input
        type="password" autoFocus placeholder="新读口令（≥8位）"
        value={newPw} disabled={busy}
        onChange={(e) => setNewPw(e.target.value)}
      />
      <p className="hint">
        {oldKek ? '✅ 旧读口令 KEK 已在内存' : '⚠️ 请先在下方解锁旧读口令'}
      </p>
      {cryptoParams?.reader && (
        <span className="tiny">当前 epoch: {cryptoParams.reader.key_epoch}</span>
      )}
      <div className="editor-actions">
        <button className="primary" disabled={busy || !newPw || !oldKek} onClick={go}>
          {busy ? (progress || '轮换中…') : '执行轮换'}
        </button>
        <button className="ghost" onClick={onClose}>取消</button>
      </div>
      {err && <p className="error">{err}</p>}
    </dialog>
  );
}