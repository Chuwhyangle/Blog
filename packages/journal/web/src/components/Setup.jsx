/** 首次初始化向导（一次性的关键流程）：
 *  1. 设置管理员密码（登录身份，替代 passkey）
 *  2. 设置主口令 + 读口令 → 服务端存 KDF 参数/verifier/口令哈希
 *  3. 生成签名密钥对 → 托管（恢复码加密后上传）→ 本地存不可导出副本
 *  4. 生成恢复码 → 物理保存确认
 */
import { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { useStore } from '../lib/store';
import { idbPut, KEYS } from '../lib/idb';
import {
  deriveKEK, KDF_PARAMS, RECOVERY_SALT, generateSigningKeyPair, bytesToHex, b64encode, uuidv7Bytes,
  aesGcmEncrypt, verifyKEK,
} from '../lib/crypto';

export default function Setup({ onDone }) {
  const { setSession, setKek, setSigningKey, setSigningKeyId, keys, cryptoParams } = useStore();
  const [step, setStep] = useState(null);        // null=正在探测进度；0 管理员密码 → 1 口令 → 2 恢复码
  const [cryptoAlreadySet, setCryptoAlreadySet] = useState(false);   // 口令已存在 → Step1 变解锁模式
  const [adminPw, setAdminPw] = useState('');
  const [adminPw2, setAdminPw2] = useState('');
  const [mainPw, setMainPw] = useState('');
  const [mainPw2, setMainPw2] = useState('');
  const [readerPw, setReaderPw] = useState('');
  const [recCode, setRecCode] = useState('');
  const [recSaved, setRecSaved] = useState(false);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  // 断点续走：探测已完成的步骤，直接从下一步开始（半初始化刷新不丢进度）
  useEffect(() => {
    (async () => {
      try {
        const s = await api.setupStatus();
        setCryptoAlreadySet(s.crypto_params_set);
        if (s.signing_key_set) { onDone(); return; }          // 已完整初始化（理论走不到这里）
        if (s.crypto_params_set) setStep(1);                  // 口令已设 → 解锁（或重设）后进密钥步骤
        else if (s.admin_password_set) setStep(1);            // 密码已设 → 口令
        else setStep(0);
      } catch {
        setStep(0);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Step 0：设置管理员密码（服务端 Argon2id 哈希，建 owner 会话）──
  async function setAdminPassword() {
    setBusy(true); setErr('');
    try {
      if (adminPw.length < 8) throw new Error('管理员密码至少 8 位');
      if (adminPw !== adminPw2) throw new Error('两次输入不一致');
      await api.setupAdminPassword(adminPw);
      setSession({ role: 'owner', can_write: true, credential_label: '管理员' });
      setStep(1);
    } catch (e) {
      setErr(e.message || '保存失败');
    } finally {
      setBusy(false);
    }
  }

  // ── Step 1：设置口令（主 + 读）──
  async function setPasswords() {
    setBusy(true); setErr('');
    try {
      if (mainPw.length < 8) throw new Error('主口令至少 8 位');
      if (mainPw !== mainPw2) throw new Error('两次输入不一致');
      if (readerPw.length < 8) throw new Error('读口令至少 8 位');

      // 派生 KEK_owner / KEK_reader（先本地派生，salt 用随机）
      const saltOwner = crypto.getRandomValues(new Uint8Array(32));
      const saltReader = crypto.getRandomValues(new Uint8Array(32));
      const kekOwner = await deriveKEK(mainPw, saltOwner, KDF_PARAMS.owner);
      const kekReader = await deriveKEK(readerPw, saltReader, KDF_PARAMS.reader);
      setKek('owner', kekOwner);
      setKek('reader', kekReader);

      // verifier：AES-GCM(固定串, KEK) —— 用于区分口令错/数据损坏（③ crypto_params）
      const fixed = new TextEncoder().encode('journal-verifier-v1');
      const verifierIv = crypto.getRandomValues(new Uint8Array(12));
      const verifier = await aesGcmEncrypt(kekOwner, fixed, verifierIv);
      const readerVerifierIv = crypto.getRandomValues(new Uint8Array(12));
      const readerVerifier = await aesGcmEncrypt(kekReader, fixed, readerVerifierIv);

      // 服务端存参数 + verifier + 读口令哈希（独立 Argon2 服务端哈希）
      const res = await fetch('/api/setup/passwords', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          owner: {
            salt: b64encode(saltOwner), params: KDF_PARAMS.owner,
            verifier: b64encode(verifier), verifier_iv: b64encode(verifierIv),
          },
          reader: {
            salt: b64encode(saltReader), params: KDF_PARAMS.reader,
            verifier: b64encode(readerVerifier), verifier_iv: b64encode(readerVerifierIv),
            password: readerPw,   // 服务端做独立 Argon2id 哈希（只读口令需在线校验）
          },
        }),
      });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.detail || '口令保存失败');
      }
      setStep(2);
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  // ── Step 1（半初始化续走）：口令已设 → 输主口令派生 KEK（内存）──
  async function unlockKeys() {
    setBusy(true); setErr('');
    try {
      if (!keys.owner) {
        const params = cryptoParams?.owner;
        if (!params) throw new Error('服务端未初始化 KDF 参数');
        const kek = await deriveKEK(mainPw, params.salt, params.params);
        // verifier 校验（③ crypto_params）：输错口令直接报错，
        // 而不是带着错误 KEK 继续走后续步骤
        const ok = await verifyKEK(params, kek);
        if (!ok) throw new Error('口令错误（verifier 校验未通过）');
        setKek('owner', kek);
      }
      setStep(2);
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  // ── Step 2：生成签名密钥 + 恢复码 + 托管 ──
  async function generateKeys() {
    setBusy(true); setErr('');
    try {
      // 1. 生成签名密钥对（extractable 仅此刻）
      const kp = await generateSigningKeyPair();
      const skId = uuidv7Bytes();

      // 2. 本地存不可导出副本（IndexedDB）—— 私钥 + key_id 一起，刷新后能恢复签名
      await idbPut(KEYS.SIGNING_KEY, { key: kp.privateKey, keyId: Array.from(skId) });
      setSigningKey(kp.privateKey);
      setSigningKeyId(skId);

      // 3. 生成恢复码（32B 随机 → base32 便于抄写）
      const rc = crypto.getRandomValues(new Uint8Array(32));
      const rec = b64encode(rc).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      setRecCode(rec);

      // 4. 托管：Enc(KEK_recovery, KEK_owner) + Enc(KEK_recovery, sk)
      //    KEK_recovery 用固定 salt 派生（RECOVERY_SALT）——恢复时才能重派生同一 KEK
      const kekRecovery = await deriveKEK(rec, RECOVERY_SALT, KDF_PARAMS.recovery);
      const wrappedKekIv = crypto.getRandomValues(new Uint8Array(12));
      const wrappedKek = await aesGcmEncrypt(kekRecovery, keys.owner, wrappedKekIv);
      const wrappedSkIv = crypto.getRandomValues(new Uint8Array(12));
      const wrappedSk = await aesGcmEncrypt(kekRecovery, kp.rawPrivatePkcs8, wrappedSkIv);

      await api.uploadEscrow({
        wrapped_kek: b64encode(wrappedKek),
        wrapped_kek_iv: b64encode(wrappedKekIv),
        wrapped_sk: b64encode(wrappedSk),
        wrapped_sk_iv: b64encode(wrappedSkIv),
        recovery_code: rec,   // 首次初始化：服务端存 Argon2id 哈希（恢复码换 elevated 会话用）
      });

      // 5. 注册签名公钥到服务端（公钥在生成瞬间已导出，verifyKey 本身不可导出）
      const raw48 = kp.rawPublicSpki.slice(-32);   // Ed25519 公钥就是最后 32B
      const res = await fetch('/api/setup/signing-key', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key_id: bytesToHex(skId), public_key: b64encode(raw48) }),
      });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.detail || '公钥注册失败');
      }
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  // ── ⌘ 完成 ──
  async function finish() {
    if (!recSaved) { setErr('请确认已离线保存恢复码'); return; }
    onDone();
  }

  return (
    <div className="setup-wrap">
      <div className="setup-card">
        <h1>📔 首次设置</h1>
        {step === null && <p className="hint">正在检查初始化进度…</p>}
        {step !== null && (
        <>
        <div className="steps">
          <span className={step >= 0 ? 'done' : ''}>1 管理员密码</span>
          <span className={step >= 1 ? 'done' : ''}>2 口令</span>
          <span className={step >= 2 ? 'done' : ''}>3 密钥与恢复码</span>
        </div>

        {step === 0 && (
          <div>
            <p>设置<b>管理员密码</b>（登录身份，可以写日记）。</p>
            <input type="password" placeholder="管理员密码（≥8位）" value={adminPw} onChange={(e) => setAdminPw(e.target.value)} />
            <input type="password" placeholder="确认管理员密码" value={adminPw2} onChange={(e) => setAdminPw2(e.target.value)} />
            <button className="primary" disabled={busy || !adminPw || !adminPw2} onClick={setAdminPassword}>
              {busy ? '保存中…' : '设置并继续'}
            </button>
          </div>
        )}

        {step === 1 && (
          <div>
            {cryptoAlreadySet ? (
              <>
                <p>口令已设置。输入<b>主口令</b>解锁加密密钥（仅存内存）。</p>
                <input type="password" placeholder="主口令" value={mainPw} autoFocus onChange={(e) => setMainPw(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && unlockKeys()} />
                <button className="primary" disabled={busy || !mainPw} onClick={unlockKeys}>{busy ? '解锁中…' : '解锁并继续'}</button>
              </>
            ) : (
              <>
                <p>设置主口令（本人解锁私人条目）与读口令（访客读共享条目）。</p>
                <input type="password" placeholder="主口令（≥8位）" value={mainPw} onChange={(e) => setMainPw(e.target.value)} />
                <input type="password" placeholder="确认主口令" value={mainPw2} onChange={(e) => setMainPw2(e.target.value)} />
                <input type="password" placeholder="访客读口令（≥8位）" value={readerPw} onChange={(e) => setReaderPw(e.target.value)} />
                <button className="primary" disabled={busy} onClick={setPasswords}>{busy ? '保存中…' : '保存口令'}</button>
              </>
            )}
          </div>
        )}

        {step === 2 && (
          <div>
            {!recCode ? (
              <button className="primary" disabled={busy} onClick={generateKeys}>
                {busy ? '生成中…' : '生成密钥与恢复码'}
              </button>
            ) : (
              <div className="recover-box">
                <p className="hint">⚠️ 请把下面的恢复码<b>抄写到纸上</b>或存入离线密码管理器。</p>
                <code className="recover-code">{recCode}</code>
                <label className="check">
                  <input type="checkbox" checked={recSaved} onChange={(e) => setRecSaved(e.target.checked)} />
                  我已离线保存恢复码（丢失 = 永久失去全部私人内容）
                </label>
                <button className="primary" disabled={!recSaved} onClick={finish}>完成设置</button>
              </div>
            )}
          </div>
        )}

        {err && <p className="error">{err}</p>}
        </>
        )}
      </div>
    </div>
  );
}
