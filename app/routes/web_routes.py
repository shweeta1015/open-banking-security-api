"""Frontend Web Delivery Routes."""
from pathlib import Path
from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse

router = APIRouter(tags=["Frontend Views"])

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"


@router.get("/", response_class=FileResponse)
def index_page():
    return FileResponse(FRONTEND_DIR / "index.html")


@router.get("/dashboard", response_class=FileResponse)
def dashboard_page():
    return FileResponse(FRONTEND_DIR / "index.html")


@router.get("/consent", response_class=FileResponse)
def consent_page():
    return FileResponse(FRONTEND_DIR / "consent.html")


@router.get("/oauth/callback", response_class=HTMLResponse)
def oauth_callback_page():
    """Educational callback receiver explaining authorization code handoff."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>OAuth 2.0 Callback Receiver</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; display: flex; justify-content: center; }
            .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 32px; max-width: 600px; width: 100%; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); }
            h2 { color: #38bdf8; margin-top: 0; }
            .code-box { background: #0f172a; border: 1px solid #475569; border-radius: 6px; padding: 12px; font-family: monospace; word-break: break-all; color: #4ade80; margin: 16px 0; }
            .btn { display: inline-block; background: #3b82f6; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: 500; margin-top: 16px; }
            .btn:hover { background: #2563eb; }
            .meta { color: #94a3b8; font-size: 0.9em; margin-bottom: 8px; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>OAuth 2.0 Authorization Callback</h2>
            <p class="meta">The Authorization Server redirected here with the single-use Authorization Code:</p>
            <div id="codeDisplay" class="code-box">Extracting parameters...</div>
            <p class="meta">State Token (CSRF Validation):</p>
            <div id="stateDisplay" class="code-box">...</div>
            <p>In a standard OAuth 2.0 flow, your application frontend or backend client now exchanges this code + PKCE code_verifier for an RS256 JWT access token.</p>
            <a href="/dashboard" class="btn" id="returnBtn">Return to Security Dashboard</a>
        </div>
        <script>
            const urlParams = new URLSearchParams(window.location.search);
            const code = urlParams.get('code');
            const state = urlParams.get('state');
            document.getElementById('codeDisplay').innerText = code || "No code parameter found";
            document.getElementById('stateDisplay').innerText = state || "No state parameter found";
            if (code) {
                sessionStorage.setItem('last_auth_code', code);
                sessionStorage.setItem('last_auth_state', state);
                document.getElementById('returnBtn').innerText = "Return to Dashboard & Exchange Code";
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
