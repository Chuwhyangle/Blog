-- journal 库 schema —— 服务端只存密文与元数据（③ + 裁决⑪ 增量）
-- 建表用 journal_ddl 用户，应用用 journal_app（仅 DML）

CREATE DATABASE IF NOT EXISTS journal
  CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE journal;

-- ── 作者签名公钥（多行，支持轮换；旧公钥永久保留打 retired_at）──
-- 必须先于 entries 建：entries.signing_key_id 有外键引用。
CREATE TABLE signing_keys (
  key_id      BINARY(16)    NOT NULL PRIMARY KEY,  -- UUIDv7
  public_key  VARBINARY(32) NOT NULL,              -- Ed25519 公钥原始字节
  created_at  DATETIME(3)   NOT NULL,
  retired_at  DATETIME(3)   NULL,                  -- NULL = 当前活跃
  note        VARCHAR(120)  NULL
) ENGINE=InnoDB;

-- ── 日记条目 ────────────────────────────────────────────────
-- 安全模型：服务端只见密文。ciphertext / iv / dek_* / signature 全部不可解读。
-- id 用 UUIDv7：前 48 位毫秒时间戳 → 聚簇索引顺序插入，避免 v4 的页分裂。
CREATE TABLE entries (
  id             BINARY(16)     NOT NULL,           -- UUIDv7
  visibility     ENUM('private','shared') NOT NULL DEFAULT 'private',
  created_at     DATETIME(3)    NOT NULL,           -- 客户端生成，签名覆盖
  updated_at     DATETIME(3)    NOT NULL,           -- 客户端生成，签名覆盖
  ciphertext     MEDIUMBLOB     NOT NULL,           -- AES-256-GCM(JSON{title,body,tags}, DEK)
  iv             BINARY(12)     NOT NULL,           -- GCM nonce，每次加密重新随机
  dek_owner      VARBINARY(48)  NOT NULL,           -- wrap(DEK, KEK_owner)：32B 密文 + 16B tag
  dek_owner_iv   BINARY(12)     NOT NULL,
  dek_reader     VARBINARY(48)  NULL,               -- private 为 NULL
  dek_reader_iv  BINARY(12)     NULL,
  signature      BINARY(64)     NOT NULL,           -- Ed25519(canonical payload)
  signing_key_id BINARY(16)     NOT NULL,           -- → signing_keys.key_id（写入后不可变）
  owner_epoch    INT UNSIGNED   NOT NULL DEFAULT 1, -- 封套用第几代 KEK_owner 包
  reader_epoch   INT UNSIGNED   NOT NULL DEFAULT 0, -- private 恒为 0
  PRIMARY KEY (id),
  KEY idx_vis_time (visibility, created_at DESC),
  CONSTRAINT fk_entries_signing_key FOREIGN KEY (signing_key_id)
    REFERENCES signing_keys (key_id)
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

-- ── KDF 参数与口令校验（按 role 分行，参数写进数据行）──────────
-- verifier = AES-GCM(固定串, KEK)，用于区分"口令错"与"数据损坏"
CREATE TABLE crypto_params (
  role        ENUM('owner','reader') NOT NULL,
  salt        VARBINARY(32) NOT NULL,
  algo        VARCHAR(16)  NOT NULL DEFAULT 'argon2id',
  params      JSON         NOT NULL,               -- {"m":65536,"t":3,"p":1}（KB/miB 语义见注释）
  verifier    VARBINARY(64) NOT NULL,              -- 固定串 48B 密文 + 16B GCM tag
  verifier_iv BINARY(12)    NOT NULL,
  key_epoch   INT UNSIGNED  NOT NULL DEFAULT 1,
  -- 服务端在线校验用（仅 reader 行非空）：Argon2id 标准编码串（$argon2id$...），
  -- 独立于前端派生 KEK 的 salt/params —— 若同盐同参，服务端拿到 hash 就等于拿到 KEK_reader。
  password_hash VARCHAR(255) NULL,
  PRIMARY KEY (role)
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

-- ── WebAuthn 凭据 ─────────────────────────────────────────
CREATE TABLE credentials (
  cred_id     VARBINARY(255)  NOT NULL,            -- WebAuthn credential ID（管理员密码模式：固定 b'admin-password'）
  public_key  VARBINARY(512)  NOT NULL,            -- COSE 公钥（密码模式留空）
  sign_count  BIGINT UNSIGNED NOT NULL DEFAULT 0,
  can_write   TINYINT(1)      NOT NULL DEFAULT 0,  -- 写权限的唯一判据（⑤ §6）
  label       VARCHAR(64)     NULL,
  password_hash VARCHAR(255)  NULL,                -- 管理员密码 Argon2id 哈希（密码登录模式）
  failed_count INT UNSIGNED   NOT NULL DEFAULT 0,  -- 密码失败计数（账号级锁）
  frozen_until DATETIME(3)    NULL,                -- 冻结截止时间
  created_at  DATETIME(3)     NOT NULL,
  PRIMARY KEY (cred_id)
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

-- ── 恢复码托管（裁决⑩ Q2：包 KEK_owner + 签名私钥，全局一行）──
CREATE TABLE key_escrow (
  purpose       VARCHAR(32)    NOT NULL PRIMARY KEY, -- 'recovery'
  code_hash     VARBINARY(255) NOT NULL,             -- Argon2id(恢复码)，在线校验用
  wrapped_kek   VARBINARY(64)  NOT NULL,             -- Enc(KEK_recovery, KEK_owner)
  wrapped_kek_iv VARBINARY(12) NOT NULL,
  wrapped_sk    VARBINARY(128) NULL,                 -- Enc(KEK_recovery, pkcs8 私钥)
  wrapped_sk_iv VARBINARY(12)  NULL,
  created_at    DATETIME(3)    NOT NULL,
  used_at       DATETIME(3)    NULL,                 -- 用过即作废
  failed_count  INT UNSIGNED   NOT NULL DEFAULT 0,   -- 失败计数（应用层冻结）
  frozen_until  DATETIME(3)    NULL                  -- 冻结截止时间
) ENGINE=InnoDB;

-- ── 会话（服务端表，主键存 SHA-256(token)）──────────────────
CREATE TABLE sessions (
  id            BINARY(32)   NOT NULL PRIMARY KEY,  -- SHA-256(随机 token)
  role          ENUM('owner','reader','elevated') NOT NULL,
  credential_id VARBINARY(255) NULL,                -- WebAuthn 登录时指向 credentials
  can_write     TINYINT(1)   NOT NULL DEFAULT 0,    -- 快速拒绝路径；放行必须回查 credentials
  created_at    DATETIME(3)  NOT NULL,
  expires_at    DATETIME(3)  NOT NULL,
  last_seen_at  DATETIME(3)  NOT NULL,
  ip            VARBINARY(16) NULL,
  user_agent    VARCHAR(255)  NULL,
  KEY idx_expires (expires_at)
) ENGINE=InnoDB;

-- ── WebAuthn challenge（删除即校验，防重放）──────────────────
CREATE TABLE webauthn_challenges (
  challenge  BINARY(32) NOT NULL PRIMARY KEY,
  purpose    ENUM('register','authenticate') NOT NULL,
  expires_at DATETIME(3) NOT NULL,
  KEY idx_expires (expires_at)
) ENGINE=InnoDB;
