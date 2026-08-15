\## 1. MySQL Schema

服务端**只见密文**。以下所有二进制列对服务器而言都是不可解读的字节串。

\```sql

CREATE DATABASE IF NOT EXISTS journal

 CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;

USE journal;

-- ── 日记条目 ────────────────────────────────────────────────

CREATE TABLE entries (

 id       CHAR(36)         NOT NULL,  -- uuid4

 visibility   ENUM('private','shared') NOT NULL DEFAULT 'private',

 created_at   DATETIME(3)        NOT NULL,

 updated_at   DATETIME(3)        NOT NULL,

 ciphertext   MEDIUMBLOB   NOT NULL,  -- AES-256-GCM(JSON{title,body,tags}, DEK)

 iv       BINARY(12)   NOT NULL,  -- GCM nonce，每次加密重新随机

 dek_owner    VARBINARY(48) NOT NULL,  -- wrap(DEK,KEK_owner)：32B 密文 + 16B tag

 dek_owner_iv  BINARY(12)   NOT NULL,

 dek_reader   VARBINARY(48) NULL,    -- private 条目为 NULL

 dek_reader_iv  BINARY(12)   NULL,

 signature    BINARY(64)   NOT NULL,  -- Ed25519 定长 64 字节

 key_epoch    INT UNSIGNED  NOT NULL DEFAULT 1,

 PRIMARY KEY (id),

 KEY idx_vis_time (visibility, created_at DESC)

) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

-- 标题也在 ciphertext 内，明文列不含任何正文信息。

-- created_at / visibility 是刻意保留的明文元数据（用于排序与分流）。

-- ── KDF 参数与口令校验 ──────────────────────────────────────

CREATE TABLE crypto_params (

 role      ENUM('owner','reader') NOT NULL,

 salt      VARBINARY(32) NOT NULL,

 algo      VARCHAR(16)  NOT NULL DEFAULT 'argon2id',

 params     JSON      NOT NULL,  -- {"m":65536,"t":3,"p":1}

 verifier    VARBINARY(64) NOT NULL,  -- AES-GCM(固定串, KEK)

 verifier_iv   BINARY(12)   NOT NULL,

 key_epoch    INT UNSIGNED  NOT NULL DEFAULT 1,

 PRIMARY KEY (role)

) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

-- verifier 用于区分"口令输错"与"数据损坏"。

-- 没有它，用户只会看到一个无法归因的 GCM tag mismatch。

-- ── WebAuthn 凭据 ──────────────────────────────────────────

CREATE TABLE credentials (

 cred_id     VARBINARY(255)  NOT NULL,  -- WebAuthn credential ID，长度不定

 public_key   VARBINARY(512)  NOT NULL,  -- COSE 公钥

 sign_count   BIGINT UNSIGNED NOT NULL DEFAULT 0,

 can_write    TINYINT(1)    NOT NULL DEFAULT 0,  -- 写权限的唯一判据

 label      VARCHAR(64)   NULL,    -- '主力笔记本' / 'iPhone'

 created_at   DATETIME(3)   NOT NULL,

 PRIMARY KEY (cred_id)

) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

-- ── 作者签名公钥（读者验签用）────────────────────────────────

CREATE TABLE signing_key (

 id       TINYINT UNSIGNED NOT NULL DEFAULT 1,

 public_key   BINARY(32)    NOT NULL,  -- Ed25519 公钥定长 32 字节

 PRIMARY KEY (id),

 CONSTRAINT chk_singleton CHECK (id = 1)

) ENGINE=InnoDB;

\```

\### 几处类型选择的理由

| 列 | 选型 | 理由 |

|---|---|---|

| `id` | `CHAR(36)` | 可读、好排查。规模上来才需要 `BINARY(16)` + `UUID_TO_BIN()` |

| `iv` / `dek_*_iv` | `BINARY(12)` | GCM nonce 定长，用定长类型省掉长度前缀 |

| `dek_*` | `VARBINARY(48)` | 32B 密钥密文 + 16B GCM tag |

| `signature` | `BINARY(64)` | Ed25519 签名恒为 64 字节 |

| `ciphertext` | `MEDIUMBLOB` | `BLOB` 上限 64 KB，长文可能顶到；`MEDIUMBLOB` 无额外成本 |

| `visibility` | `ENUM` | 比 `VARCHAR + CHECK` 更省，且天然约束取值 |

\> **和你正在学的 InnoDB 行格式正好对上。** `ROW_FORMAT=DYNAMIC` 下，只有当整行放不进半页（16 KB 页约 8000 字节）时，InnoDB 才把最长的变长列**整体**挪到溢出页，行内留 20 字节指针——这跟 `COMPACT` 的"本地保留 768 字节前缀"是不同策略。

\>

\> 你的日记正文加密后大多几 KB，正好在这个阈值附近来回，是个能实际观察行为的样本。可以写几条长短不一的记录，用 `INFORMATION_SCHEMA.INNODB_TABLESPACES` 配合 `innodb_ruby` 看页分布变化。

\### 明文元数据的取舍

`visibility` 和 `created_at` 是明文的，因为要用它们做分流和排序。这意味着服务器能推断"你哪天写了日记、是不是分享的"。想连这个都藏，代价是全表拉回客户端解密后再排序，分页会失效。**当前规模下不值得，先接受这个泄漏。**

\---

\## 2. 多项目共用 MySQL 的隔离（必做）

服务器上跑多个项目、共用一个 MySQL 实例时，**每个项目独立 schema + 独立用户 + 权限只到自己的 schema**。不做这一条，任何一个项目被打穿，所有项目的数据一起完蛋。

\```sql

-- 运行时用户：只有 DML，连 DROP TABLE 都执行不了

CREATE USER 'journal_app'@'127.0.0.1' IDENTIFIED BY '<强随机口令>';

GRANT SELECT, INSERT, UPDATE, DELETE ON journal.* TO 'journal_app'@'127.0.0.1';

-- 迁移用户：单独一个，只在改表结构时手动用

CREATE USER 'journal_ddl'@'127.0.0.1' IDENTIFIED BY '<另一个强随机口令>';

GRANT ALL PRIVILEGES ON journal.* TO 'journal_ddl'@'127.0.0.1';

FLUSH PRIVILEGES;

\```

**要点：**

\- FastAPI 的连接串用 `journal_app`，**不是 root，也不是 DDL 用户**。应用被注入或被打穿时，攻击者最多改本项目的数据，删不掉表、动不了别的 schema

\- 用户名后缀 `@'127.0.0.1'` 限定只能从本机连

\- MySQL `bind-address = 127.0.0.1`，安全组**不放行 3306**

\### 2C4G 上的 MySQL 调优（`/etc/mysql/my.cnf`）

\```ini

[mysqld]

bind-address = 127.0.0.1

innodb_buffer_pool_size     = 512M  # 默认会按内存自动放大，必须显式压住

innodb_buffer_pool_instances  = 1    # 小 buffer pool 分实例反而浪费

innodb_log_file_size      = 128M

innodb_flush_method       = O_DIRECT

innodb_flush_log_at_trx_commit = 1    # 日记数据，不为性能牺牲持久性

max_connections         = 60   # 多项目共用也够；每连接都吃内存

table_open_cache        = 400

tmp_table_size         = 32M

max_heap_table_size       = 32M

sort_buffer_size        = 512K  # 这几个是"每连接"分配，别调大

join_buffer_size        = 512K

character-set-server      = utf8mb4

collation-server        = utf8mb4_0900_ai_ci

\```

**关于 `performance_schema`：** 关掉能省 200–400 MB，是 2C4G 上的常规操作。但你正在做 MySQL 观测层、也在系统学内部机制——关了等于把学习和排查的手段一起砍掉。折中方案是保留但缩小：

\```ini

performance_schema           = ON

performance_schema_max_table_instances = 400

performance_schema_max_table_handles  = 800

\```

这样占用能压到 100 MB 以内，观测能力基本保留。**这是学习价值 vs 内存的取舍，你自己权衡。**

\### FastAPI 连接池

\```python

create_engine(

  url,

  pool_size=5, max_overflow=5,  # 个位数 QPS，池子不需要大

  pool_recycle=3600,       # 防长连接被静默断开

  pool_pre_ping=True,

)

\```

`pool_recycle` + `pool_pre_ping` 这两个别省。MySQL 的 `wait_timeout` 会把闲置连接断掉，而客户端不知道，下次用就报 `MySQL server has gone away`——这是 Python + MySQL 最常见的生产问题之一。

\---

\## 3. 路由表

\### `yourdomain.com` — L0

| 路径 | 鉴权 | 处理 |

|---|---|---|

| `/`、`/posts/*` | 无 | nginx 直出 Astro 静态产物 |

| `/pagefind/*` | 无 | 构建期索引，**只含 L0** |

\### `lab.yourdomain.com` — L1

| 路径 | 鉴权 | 处理 |

|---|---|---|

| `/*` | **nginx Basic Auth** | 静态文件，server 块级全覆盖 |

\### `journal.yourdomain.com` — L2

| 路径 | 方法 | 鉴权 | 额外校验 | 处理 |

|---|---|---|---|---|

| `/*` | GET | 无 | — | SPA 壳，静态文件 |

| `/api/session` | POST | — | — | 访客口令登录 → **访客 session** |

| `/api/webauthn/*` | POST | — | — | 本人设备注册 / 断言 → **本人 session** |

| `/api/entries` | GET | session | **按角色过滤** | 返回密文，服务端不解密 |

| `/api/entries` | POST/PUT/DELETE | session | **`can_write`** | 写接口 |

\> **SPA 壳可以公开，因为它不含任何数据。** 所有内容都要调 API 才拿得到，而 API 有鉴权。真正的边界在 API 上，不在页面上。

\---

\## 4. 三条进入路径

| 角色 | 认证方式 | session 类型 | 服务端返回 | 前端再输 | 能看到 | 能写 |

|---|---|---|---|---|---|---|

| **作者 · 主力电脑** | Passkey，`can_write=1` | 本人 | 全部密文 | 主口令 | 全部 | ✓ |

| **作者 · 手机** | Passkey，`can_write=0` | 本人 | 全部密文 | 主口令 | 全部 | ✗ |

| **授权访客** | 访客口令 → `/api/session` | 访客 | 仅 `shared` | 读口令 | 仅 `shared` | ✗ |

手机也注册一个 passkey，只是 `can_write=0`——**同一套凭据表，一个布尔字段区分读写**，不需要额外机制。

\### 服务端必须按 session 角色过滤 GET 结果

访客 session 请求 `/api/entries` 时，**服务端只返回 `visibility='shared'` 的行**。

这是纵深防御：即使访客在密码学上解不开 `private` 条目（DEK 根本没包给读口令），也**不应该把那些密文发给他**。少发一份密文，就少一份将来算法被攻破或口令泄露时的暴露面。

\```python

cur.execute(

  "SELECT * FROM entries "

  "WHERE (%s = 1 OR visibility = 'shared') "

  "ORDER BY created_at DESC",

  (1 if sess.is_owner else 0,),

)

\```

\---

\## 5. nginx 关键配置

\### L1 — 5 行搞定门禁

\```nginx

server {

  listen 443 ssl http2;

  server_name lab.yourdomain.com;

  root /var/www/lab;

  auth_basic      "Lab";

  auth_basic_user_file /etc/nginx/.htpasswd-lab;

  add_header X-Robots-Tag  "noindex, nofollow" always;

  add_header Cache-Control "private, no-store"  always;

}

\```

\```bash

htpasswd -c /etc/nginx/.htpasswd-lab guest   # 首次创建

htpasswd   /etc/nginx/.htpasswd-lab alice   # 追加用户（别再带 -c，会覆盖）

chmod 640 /etc/nginx/.htpasswd-lab

chown root:www-data /etc/nginx/.htpasswd-lab

\```

\### L2 — SPA + API 反代

\```nginx

server {

  listen 443 ssl http2;

  server_name journal.yourdomain.com;

  root /var/www/journal;

  add_header X-Robots-Tag "noindex, nofollow" always;

  location /api/ {

​    proxy_pass http://127.0.0.1:8000;

​    proxy_set_header Host        $host;

​    proxy_set_header X-Real-IP     $remote_addr;

​    proxy_set_header X-Forwarded-Proto $scheme;

  }

  location / {

​    try_files $uri $uri/ /index.html;   # SPA 路由回退

  }

}

\```

`127.0.0.1:8000` 只监听回环地址，阿里云安全组也不放行 8000——FastAPI 不直接对外。