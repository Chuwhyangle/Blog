# leyanwc.xyz — 个人站点（L0 / L1 / L2 三层）

架构总览与阶段计划见 `Doc/开发文档/①~⑥` 及实施裁决 `⑩/⑪`（Doc 区）。

```
leyanwc.xyz            L0  公开技术博客   Astro 静态产物，nginx 直出
lab.leyanwc.xyz        L1  静态 demo      nginx Basic Auth（口令区）
journal.leyanwc.xyz    L2  个人日记       React SPA + FastAPI + MySQL（客户端加密）
```

## 目录

```
packages/
  public/    # L0  Astro 源码
  lab/       # L1  静态 demo（部署时 rsync 到 /var/www/lab）
  journal/   # L2  web（Vite+React SPWO）+ api（FastAPI）
deploy/
  nginx/     # 三段 nginx server 配置
  systemd/   # journal-api.service（FastAPI 开机自启）
  sql/       # schema.sql（8 张表，journal 库）
  scripts/   # P0 基线脚本、建库建用户、部署脚本
  env/       # .env 模板（数据库口令等，不进 git）
ops/
  P0_服务器基线.md     # 按顺序执行的运维手册（P0）
  P1_P2_部署.md        # L0/L1 上线步骤（P1/P2）
  P3_部署.md           # L2 日记系统部署与验证（P3）
```

## 快速索引

- 架构：`Doc/开发文档/①.md`（目标）· `②.md`（技术栈/资源）· `③.md`（数据模型/路由/nginx）
- L1 门禁：`Doc/开发文档/④.md`
- L2 加密设计：`Doc/开发文档/⑤.md`
- 安全清单/分阶段/版本记录：`Doc/开发文档/⑥.md`
- 密钥生命周期裁决：`Doc/实施裁决/⑩ 实施裁决 A.md`
- 会话/KDF/设备裁决 + Schema 增量：`Doc/实施裁决/⑪ 实施裁决 B.md`