/** 编辑器：新建/编辑日记 —— 每次保存换新 DEK+IV、重包封套、重新签名（⑪ 补充①） */
import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api';
import { useStore } from '../lib/store';
import { encryptEntry } from '../lib/crypto';

export default function Editor({ entry, isOwner, signingKey, onClose, onSaved }) {
  const { cryptoParams, keys } = useStore();
  const [title, setTitle] = useState(entry.plain?.title || '');
  const [body, setBody] = useState(entry.plain?.body || '');
  const [tags, setTags] = useState(entry.plain?.tags?.join(', ') || '');
  const [visibility, setVisibility] = useState(entry.visibility || 'private');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  // 访客只读：不显示编辑控件
  const canSave = isOwner;

  // 草稿自动保存（5s 防抖）—— 先加密再落地（⑤ §4）
  const saveDraft = useCallback(async () => {
    if (!entry.id) return;
    try {
      if (!signingKey || !entry.signing_key_id_bytes) return;   // 无签名能力则不自动存
      const kekOwner = keys.owner;
      if (!kekOwner) return;
      const ownerParams = cryptoParams?.owner;
      if (!ownerParams) return;
      const payload = await encryptEntry({
        title, body, tags: tags.split(',').map(s => s.trim()).filter(Boolean),
        visibility,
        keks: { owner: kekOwner, reader: keys.reader },
        ownerEpoch: ownerParams.key_epoch,
        readerEpoch: cryptoParams?.reader?.key_epoch ?? 0,
        signingKey,
        signingKeyId: entry.signing_key_id_bytes,
      });
      await api.updateEntry(entry.id, { ...payload, id: entry.id });
    } catch {
      // 静默失败，下次手动保存报错
    }
  }, [entry.id, entry.signing_key_id_bytes, signingKey, keys.owner, keys.reader, cryptoParams, title, body, tags, visibility]);

  useEffect(() => {
    if (!canSave || !entry.id) return;   // 只有编辑已有条目时自动保存
    const t = setTimeout(() => { saveDraft(); }, 5000);
    return () => clearTimeout(t);
  }, [title, body, tags, visibility, canSave, entry.id, saveDraft]);

  async function save() {
    setBusy(true); setErr('');
    try {
      if (!canSave) return;
      if (!signingKey || !entry.signing_key_id_bytes) {
        throw new Error('签名密钥未加载，无法写日记');
      }
      const kekOwner = keys.owner;
      if (!kekOwner) throw new Error('请先解锁主口令');
      const ownerParams = cryptoParams?.owner;
      if (!ownerParams) throw new Error('未初始化 crypto 参数');
      const readerKek = keys.reader;
      // 若是 shared 但没有 reader KEK，需要先输读口令（个人场景作者通常已解）
      if (visibility === 'shared' && !readerKek) {
        throw new Error('共享条目需要读口令（先解锁读口令）');
      }

      const payload = await encryptEntry({
        title, body, tags: tags.split(',').map(s => s.trim()).filter(Boolean),
        visibility,
        keks: { owner: kekOwner, reader: readerKek },
        ownerEpoch: ownerParams.key_epoch,
        readerEpoch: cryptoParams?.reader?.key_epoch ?? 0,
        signingKey,
        signingKeyId: entry.signing_key_id_bytes,
      });

      if (entry.id) {
        await api.updateEntry(entry.id, payload);
      } else {
        await api.createEntry(payload);
      }
      onSaved();
    } catch (e) {
      setErr(e.message || '保存失败');
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!window.confirm('确认删除这篇日记？')) return;
    try {
      await api.deleteEntry(entry.id);
      onSaved();
    } catch (e) {
      setErr(e.message);
    }
  }

  return (
    <dialog open className="modal editor">
      <div className="editor-top">
        <input
          className="title-input"
          placeholder="标题"
          value={title}
          disabled={!canSave}
          onChange={(e) => setTitle(e.target.value)}
        />
        <div className="vis-box">
          <label className={`pill ${visibility === 'private' ? 'on' : ''}`}>
            <input type="radio" name="vis" checked={visibility === 'private'}
              onChange={() => setVisibility('private')} disabled={!canSave} />
            🔒 私密
          </label>
          <label className={`pill ${visibility === 'shared' ? 'on' : ''}`}>
            <input type="radio" name="vis" checked={visibility === 'shared'}
              onChange={() => setVisibility('shared')} disabled={!canSave} />
            🔓 共享
          </label>
        </div>
      </div>
      <textarea
        className="body-input"
        placeholder="写点什么…"
        value={body}
        disabled={!canSave}
        onChange={(e) => setBody(e.target.value)}
      />
      <input
        className="tags-input"
        placeholder="标签（逗号分隔）"
        value={tags}
        disabled={!canSave}
        onChange={(e) => setTags(e.target.value)}
      />
      {err && <p className="error">{err}</p>}
      <div className="editor-actions">
        {canSave && <button className="primary" disabled={busy} onClick={save}>{busy ? '加密保存中…' : '💾 保存'}</button>}
        {canSave && entry.id && <button className="danger ghost" onClick={remove}>删除</button>}
        <button className="ghost" onClick={onClose}>关闭</button>
      </div>
      <p className="tiny">内容在浏览器内加密后上传；保存时自动更换 DEK/IV 并重新签名。</p>
    </dialog>
  );
}