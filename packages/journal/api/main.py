"""Journal API 入口：密文 CRUD + WebAuthn + 会话 + 恢复（② FastAPI）"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes import entries, webauthn, credentials, auth, setup

app = FastAPI(title="Journal API", version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json")

# 同源部署（journal.leyanwc.xyz 的 SPA + API），CORS 其实不需要；
# 保留严格配置以防未来静态分离：只允许本站点来源。
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://journal.leyanwc.xyz"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(webauthn.router)
app.include_router(credentials.router)
app.include_router(entries.router)
app.include_router(setup.router)


@app.get("/api/health")
def health():
    return {"ok": True}