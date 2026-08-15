/** 首次初始化向导（一次性的关键流程）：
 *  1. 注册主人 passkey（can_write=1）
 *  2. 设置主口令 + 读口令 → 服务端存 KDF 参数/verifier/口令哈希
 *  3. 生成签名密钥对 → 托管（恢复码加密后上传）→ 本地存不可导出副本
 *  4. 生成恢复码 → 物理保存确认
 */
import { useState } from 'react';
import { api } from '../lib/api';
import { useStore } from '../lib/store';
import { idbPut, KEYS } from '../lib/idb';
import {
  deriveKEK, KDF_PARAMS, generateSigningKeyPair, bytesToHex, b64encode, uuidv7Bytes,
  aesGcmEncrypt,
} from '../lib/crypto';

export default function Setup({ onDone }) {
  const { setSession, setKek, setSigningKey, setSigningKeyId, keys } = useStore();
  const [step, setStep] = useState(0);           // 0 passkey → 1 口令 → 2 恢复码
  const [mainPw, setMainPw] = useState('');
  const [mainPw2, setMainPw2] = useState('');
  const [readerPw, setReaderPw] = useState('');
  const [recCode, setRecCode] = useState('');
  const [recSaved, setRecSaved] = useState(false);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  // ── Step 0：注册主人 passkey ──
  async function registerPasskey() {
    setBusy(true); setErr('');
    try {
      const opts = await api.webauthnRegisterOptions(true);   // can_write=1（elevated 才能注册写钥匙）
      // ⚠️ 首次初始化时没有 elevated 会话 —— 需要一个"初始化专属"流程：
      // 服务端在"零凭据"状态下放行首个 can_write=1 注册（bootstrap）。
      // 需要在路由里补：若 credentials 表为空 → 允许注册写凭据（无需 elevated）。
      const cred = await navigator.credentials.create({
        publicKey: {
          challenge: b64urlToBytes(opts.challenge),
          rp: { id: opts.rp_id, name: opts.rp_name },
          user: {
            id: b64urlToBytes(opts.user_id),
            name: opts.user_name,
            displayName: opts.user_display_name,
          },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],   // ES256
          timeout: 120000,
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            residentKey: 'required',
            userVerification: 'required',
          },
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
            attestationObject: b64url(cred.response.attestationObject),
          },
          challenge: b64url(opts.challenge),
        },
        label: '主力机',
        can_write: true,
      };
      await api.webauthnRegisterVerify(body);
      setSession({ role: 'owner', can_write: true, credential_label: '主力机' });
      setStep(1);
    } catch (e) {
      setErr(e.message || 'passkey 注册失败');
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
      const kekRecovery = await deriveKEK(rec, crypto.getRandomValues(new Uint8Array(32)), KDF_PARAMS.recovery);
      const wrappedKekIv = crypto.getRandomValues(new Uint8Array(12));
      const wrappedKek = await aesGcmEncrypt(kekRecovery, keys.owner, wrappedKekIv);
      const wrappedSkIv = crypto.getRandomValues(new Uint8Array(12));
      const wrappedSk = await aesGcmEncrypt(kekRecovery, kp.rawPrivatePkcs8, wrappedSkIv);

      await api.uploadEscrow({
        wrapped_kek: b64encode(wrappedKek),
        wrapped_kek_iv: b64encode(wrappedKekIv),
        wrapped_sk: b64encode(wrappedSk),
        wrapped_sk_iv: b64encode(wrappedSkIv),
      });

      // 5. 注册签名公钥到服务端
      const pub = await crypto.subtle.exportKey('spki', kp.publicKey);
      const raw48 = new Uint8Array(pub).slice(-32);   // Ed25519 公钥就是最后 32B
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
        <div className="steps">
          <span className={step >= 0 ? 'done' : ''}>1 Passkey</span>
          <span className={step >= 1 ? 'done' : ''}>2 口令</span>
          <span className={step >= 2 ? 'done' : ''}>3 密钥与恢复码</span>
        </div>

        {step === 0 && (
          <div>
            <p>注册本机 passkey 作为<b>主人身份</b>（可以写日记）。</p>
            <button className="primary" disabled={busy} onClick={registerPasskey}>
              {busy ? '注册中…' : '注册主人 Passkey'}
            </button>
          </div>
        )}

        {step === 1 && (
          <div>
            <p>设置主口令（本人解锁私人条目）与读口令（访客读共享条目）。</p>
            <input type="password" placeholder="主口令（≥8位）" value={mainPw} onChange={(e) => setMainPw(e.target.value)} />
            <input type="password" placeholder="确认主口令" value={mainPw2} onChange={(e) => setMainPw2(e.target.value)} />
            <input type="password" placeholder="访客读口令（≥8位）" value={readerPw} onChange={(e) => setReaderPw(e.target.value)} />
            <button className="primary" disabled={busy} onClick={setPasswords}>{busy ? '保存中…' : '保存口令'}</button>
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
      </div>
    </div>
  );
}

function b64urlToBytes(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return b;
}