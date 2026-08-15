## 1. L1 就是 nginx 的 5 行配置

```nginx
auth_basic           "Lab";
auth_basic_user_file /etc/nginx/.htpasswd-lab;
```

写在 `server` 块里，**该 server 下所有路径自动全覆盖**——包括 demo 子目录里的 CSS、JS、图片、字体。访客访问任何一个资源，nginx 都会先要凭据。

这就是全部。没有网关代码，没有 catch-all 路由，没有路径穿越风险，没有 Content-Type 处理。**半天上线。**

### 对比前两版被迫做的事

| | 需要防什么 | 需要写什么 |
|---|---|---|
| Next.js on VPS | `public/` 绕过 middleware | catch-all 网关 + 路径规范化 + MIME 处理 |
| Cloudflare Pages | `*.pages.dev` 绕过 Access | 额外的 Access 应用配置（两条） |
| **nginx** | **无** | **无** |

nginx 的鉴权作用在 server 块上，不存在"某类资源绕过中间件"的模型。前两版那些复杂度，本质上都是在补别人架构的漏。

---

## 2. Basic Auth 的取舍

**优点**

- 零代码，5 行配置
- 浏览器原生弹窗，无需实现登录页
- **大陆秒开**——不访问任何境外服务

**缺点**

- UI 无法自定义
- 没有"登出"按钮（浏览器缓存凭据，需关闭浏览器或清凭据）
- 每个请求都携带凭据（HTTPS 下不是问题）

对"发一组口令给朋友看 demo"这个需求，**够了**。

> 这也是不用 Cloudflare Access 的第二个理由：Access 的登录流程本身要访问 Cloudflare 境外服务，大陆访客会卡在登录页——门禁比内容还慢。

---

## 3. 升级路径：自定义登录页（P2 之后再说）

如果以后想要好看的登录页和可控的会话，用 nginx `auth_request`，**不要改成前端校验**：

```nginx
location / {
    auth_request /_auth;
    error_page 401 = @login;
    root /var/www/lab;
}

location = /_auth {
    internal;
    proxy_pass http://127.0.0.1:8000/api/gate/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
}

location @login {
    return 302 /login.html;
}
```

FastAPI 提供 `/api/gate/verify`（校验签名 cookie）和一个登录接口。

**关键在于 nginx 仍然负责拦截每一个资源请求**——每个 CSS / JS / 图片都会先走 `auth_request`。这样既有自定义 UI，又不会退化成"HTML 有保护但资源裸奔"。

配套：口令用 Argon2id 哈希存服务端（不是明文、不是 MD5），加失败限流：

```nginx
limit_req_zone $binary_remote_addr zone=gate:10m rate=5r/m;
```

---

## 4. 为什么 Demo 必须独立子域

**这是安全边界，不是审美选择。**

如果 demo 和日记同源，任意一个 demo 里的 XSS 都能带着你的会话去打 `/api/entries`。HttpOnly 挡得住 JS **读** cookie，**挡不住 JS 发带 cookie 的请求**。

你自己写的 demo 也许没有 XSS，但 demo 的性质就是实验性代码——这正是最容易出漏洞的地方。放在 `lab.` 独立子域，浏览器同源策略天然隔离，demo 里的脚本够不着 `journal.` 的任何东西。

子域名不需要额外备案（备案只针对顶级域名），所以这层隔离是**白送的**。

---

## 5. 静态文件怎么放

直接放 `/var/www/lab/`，nginx `root` 指过去就行。

**不需要藏进任何 "private" 目录。** 这跟 Next.js 完全不同——nginx 里没有"静态资源走另一条不经过鉴权的路径"这回事，`auth_basic` 在 server 层拦截所有请求。

```
/var/www/lab/
├── index.html              # demo 索引页，手写或脚本生成
├── color-picker/
│   ├── index.html
│   ├── style.css
│   └── app.js
└── canvas-toy/
    └── index.html
```

部署就是 `rsync` 或 `git pull` + 复制。