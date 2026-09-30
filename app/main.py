"""FastAPI Main Application Factory for OpenBankingSecurityAPI Simulator."""
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from app.config import get_settings
from app.database import init_db, SessionLocal
from app.security.crypto import ensure_rsa_keys
from app.seed import seed_database
from app.routes import auth_routes, partner_routes, banking_routes, audit_routes, web_routes

settings = get_settings()
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup & shutdown events."""
    # Ensure RSA signing keys exist
    ensure_rsa_keys()
    # Initialize DB schema
    init_db()
    # Seed dummy demo partner and bank records
    db = SessionLocal()
    try:
        seed_database(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "Local Open Banking API Security Simulator demonstrating Partner API Keys, "
        "OAuth 2.0 PKCE, RS256 JWT & JWKS, BOLA/IDOR protection, Data Minimization, "
        "DPoP Replay Defense, and OWASP API Security Top 5 mitigations."
    ),
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration for browser simulation
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def rate_limit_header_middleware(request: Request, call_next):
    """Injects standard rate limit headers from request state into HTTP response."""
    response = await call_next(request)
    rate_headers = getattr(request.state, "rate_limit_headers", None)
    if rate_headers and isinstance(rate_headers, dict):
        for k, v in rate_headers.items():
            response.headers[k] = str(v)
    return response


# Mount static assets (css, js)
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

# Register Routers
app.include_router(web_routes.router)
app.include_router(auth_routes.router)
app.include_router(partner_routes.router)
app.include_router(banking_routes.router)
app.include_router(audit_routes.router)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
