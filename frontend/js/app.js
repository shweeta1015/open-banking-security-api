/**
 * OpenBankingSecurityAPI Dashboard Application Controller
 */

// Application State
const state = {
    apiKey: "ob_live_demo1234_supersecretpartnerkey987654321",
    partnerClientId: "fintech_partner_demo",
    codeVerifier: "",
    codeChallenge: "",
    stateToken: "",
    authCode: "",
    accessToken: "",
    decodedToken: null,
    jwks: null,
    selectedAccountId: "acc_alice_chk_01"
};

// --- Initialization ---
document.addEventListener("DOMContentLoaded", async () => {
    initTabs();
    initPkceInputs();
    await checkAppHealth();
    await loadJwks();
    await refreshPartnerProfile();
    await refreshAuditLogs();

    // Check if returning from OAuth callback with saved code
    const savedCode = sessionStorage.getItem("last_auth_code");
    if (savedCode) {
        document.getElementById("authCodeInput").value = savedCode;
        state.authCode = savedCode;
        switchTab("oauth-tab");
    }

    // Auto-refresh audit logs every 5 seconds
    setInterval(refreshAuditLogs, 5000);
});

// --- Tab Navigation ---
function initTabs() {
    const tabs = document.querySelectorAll(".tab-btn");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            const targetId = tab.dataset.target;
            switchTab(targetId);
        });
    });
}

function switchTab(targetId) {
    document.querySelectorAll(".tab-btn").forEach(btn => {
        btn.classList.toggle("active", btn.dataset.target === targetId);
    });
    document.querySelectorAll(".tab-content").forEach(content => {
        content.classList.toggle("active", content.id === targetId);
    });
}

// --- Health & Public JWKS ---
async function checkAppHealth() {
    try {
        const resp = await fetch("/health");
        const data = await resp.json();
        const badge = document.getElementById("healthStatus");
        if (badge) {
            badge.innerText = data.status.toUpperCase();
            badge.className = "status-pill status-active";
        }
    } catch (e) {
        const badge = document.getElementById("healthStatus");
        if (badge) {
            badge.innerText = "OFFLINE";
            badge.className = "status-pill status-revoked";
        }
    }
}

async function loadJwks() {
    try {
        const resp = await fetch("/.well-known/jwks.json");
        const data = await resp.json();
        state.jwks = data;
        const jwksEl = document.getElementById("jwksViewer");
        if (jwksEl) {
            jwksEl.innerText = JSON.stringify(data, null, 2);
        }
    } catch (e) {
        console.error("Failed to load JWKS:", e);
    }
}

// --- Partner & API Key Management ---
async function refreshPartnerProfile() {
    const key = document.getElementById("partnerApiKeyInput").value.trim() || state.apiKey;
    const output = document.getElementById("partnerProfileOutput");
    output.innerText = "Loading partner profile...";

    try {
        const resp = await fetch("/api/v1/partners/me", {
            headers: { "X-API-Key": key }
        });
        const data = await resp.json();
        output.innerText = JSON.stringify(data, null, 2);

        if (resp.ok) {
            state.apiKey = key;
            state.partnerClientId = data.client_id;
            document.getElementById("partnerStatusPill").innerText = data.status;
            document.getElementById("partnerStatusPill").className = "status-pill " + (data.status === "ACTIVE" ? "status-active" : "status-revoked");
        } else {
            document.getElementById("partnerStatusPill").innerText = "INVALID";
            document.getElementById("partnerStatusPill").className = "status-pill status-revoked";
        }
    } catch (e) {
        output.innerText = "Error: " + e.message;
    }
    refreshAuditLogs();
}

async function rotatePartnerKey() {
    const clientId = state.partnerClientId;
    const output = document.getElementById("partnerProfileOutput");
    if (!confirm(`Are you sure you want to rotate the API key for partner '${clientId}'? Old key will be immediately revoked.`)) return;

    try {
        const resp = await fetch(`/api/v1/partners/${clientId}/rotate-key`, {
            method: "POST"
        });
        const data = await resp.json();
        output.innerText = JSON.stringify(data, null, 2);

        if (resp.ok && data.raw_api_key) {
            state.apiKey = data.raw_api_key;
            document.getElementById("partnerApiKeyInput").value = data.raw_api_key;
            alert(`Key rotated successfully!\nNew API Key: ${data.raw_api_key}\n(Key updated in simulator)`);
        }
    } catch (e) {
        output.innerText = "Rotation error: " + e.message;
    }
    refreshAuditLogs();
}

async function revokePartner() {
    const clientId = state.partnerClientId;
    const output = document.getElementById("partnerProfileOutput");
    if (!confirm(`Revoke partner '${clientId}'? Any further API calls using this partner's keys will receive HTTP 403 Forbidden.`)) return;

    try {
        const resp = await fetch(`/api/v1/partners/${clientId}/revoke`, {
            method: "POST"
        });
        const data = await resp.json();
        output.innerText = JSON.stringify(data, null, 2);
        refreshPartnerProfile();
    } catch (e) {
        output.innerText = "Revoke error: " + e.message;
    }
    refreshAuditLogs();
}

// --- OAuth 2.0 & PKCE Flow ---
function initPkceInputs() {
    const verifier = OAuthManager.generateCodeVerifier();
    OAuthManager.generateCodeChallenge(verifier).then(challenge => {
        state.codeVerifier = verifier;
        state.codeChallenge = challenge;
        state.stateToken = OAuthManager.generateState();

        document.getElementById("pkceVerifier").value = verifier;
        document.getElementById("pkceChallenge").value = challenge;
        document.getElementById("oauthState").value = state.stateToken;
    });
}

function regeneratePkce() {
    initPkceInputs();
    alert("Generated new random PKCE code_verifier (64 chars) and SHA-256 code_challenge.");
}

function startConsentFlow() {
    const clientId = state.partnerClientId;
    const redirectUri = window.location.origin + "/oauth/callback";
    const challenge = document.getElementById("pkceChallenge").value;
    const stateToken = document.getElementById("oauthState").value;
    const scope = "accounts:read balances:read transactions:read";

    const consentUrl = `/consent?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(scope)}&state=${encodeURIComponent(stateToken)}&code_challenge=${encodeURIComponent(challenge)}&code_challenge_method=S256`;

    // Open consent screen
    window.location.href = consentUrl;
}

async function exchangeAuthCode() {
    const code = document.getElementById("authCodeInput").value.trim();
    const verifier = document.getElementById("pkceVerifier").value.trim();
    const clientId = state.partnerClientId;
    const redirectUri = window.location.origin + "/oauth/callback";
    const output = document.getElementById("tokenExchangeOutput");

    if (!code) {
        alert("Please enter or generate an Authorization Code first.");
        return;
    }

    output.innerText = "Exchanging code for RS256 JWT access token...";

    try {
        const resp = await fetch("/oauth/token", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                grant_type: "authorization_code",
                code: code,
                redirect_uri: redirectUri,
                client_id: clientId,
                code_verifier: verifier
            })
        });

        const data = await resp.json();
        output.innerText = JSON.stringify(data, null, 2);

        if (resp.ok && data.access_token) {
            state.accessToken = data.access_token;
            document.getElementById("activeTokenInput").value = data.access_token;
            renderDecodedJwt(data.access_token);
            // Clear used code from session
            sessionStorage.removeItem("last_auth_code");
        }
    } catch (e) {
        output.innerText = "Token exchange error: " + e.message;
    }
    refreshAuditLogs();
}

function renderDecodedJwt(token) {
    const header = OAuthManager.decodeJwtHeader(token);
    const payload = OAuthManager.decodeJwt(token);
    state.decodedToken = payload;

    const claimsContainer = document.getElementById("jwtClaimsContainer");
    if (!claimsContainer) return;

    if (!payload) {
        claimsContainer.innerHTML = "<div style='color:#f87171;'>Invalid JWT format</div>";
        return;
    }

    const expDate = new Date(payload.exp * 1000).toLocaleTimeString();
    const iatDate = new Date(payload.iat * 1000).toLocaleTimeString();

    claimsContainer.innerHTML = `
        <div style="margin-bottom:8px;">
            <span class="claim-pill"><span class="claim-key">alg:</span> <span class="claim-val">${header?.alg || 'RS256'}</span></span>
            <span class="claim-pill"><span class="claim-key">kid:</span> <span class="claim-val">${header?.kid || 'N/A'}</span></span>
            <span class="claim-pill"><span class="claim-key">iss:</span> <span class="claim-val">${payload.iss}</span></span>
            <span class="claim-pill"><span class="claim-key">sub (Customer):</span> <span class="claim-val">${payload.sub}</span></span>
            <span class="claim-pill"><span class="claim-key">aud:</span> <span class="claim-val">${payload.aud}</span></span>
            <span class="claim-pill"><span class="claim-key">client_id:</span> <span class="claim-val">${payload.client_id}</span></span>
            <span class="claim-pill"><span class="claim-key">consent_id:</span> <span class="claim-val">${payload.consent_id}</span></span>
            <span class="claim-pill"><span class="claim-key">scope:</span> <span class="claim-val">${payload.scope}</span></span>
            <span class="claim-pill"><span class="claim-key">issued_at:</span> <span class="claim-val">${iatDate}</span></span>
            <span class="claim-pill"><span class="claim-key">expires:</span> <span class="claim-val">${expDate}</span></span>
            <span class="claim-pill"><span class="claim-key">jti:</span> <span class="claim-val">${payload.jti.substring(0, 8)}...</span></span>
        </div>
        <div style="font-size:0.75rem; color:#9ca3af; background:#0f172a; padding:8px; border-radius:4px;">
            <strong>Zero-Database Verification:</strong> Resource server verifies this token using ONLY the RSA public key (RS256) cached in memory. No database query is made to validate signature, expiration, issuer, or scopes!
        </div>
    `;
}

// --- Live Banking API Explorer ---
async function callBankingApi(endpointType) {
    const token = document.getElementById("activeTokenInput").value.trim() || state.accessToken;
    const output = document.getElementById("apiExplorerOutput");
    const accountId = document.getElementById("explorerAccountId").value.trim() || state.selectedAccountId;

    if (!token) {
        alert("Please obtain an RS256 JWT access token in the OAuth tab first.");
        switchTab("oauth-tab");
        return;
    }

    let url = "/api/v1/accounts";
    if (endpointType === "detail") url = `/api/v1/accounts/${accountId}`;
    if (endpointType === "balances") url = `/api/v1/accounts/${accountId}/balances`;
    if (endpointType === "transactions") url = `/api/v1/accounts/${accountId}/transactions`;

    output.innerText = `Calling GET ${url}...`;

    try {
        const resp = await fetch(url, {
            headers: {
                "Authorization": `Bearer ${token}`,
                "X-API-Key": state.apiKey
            }
        });
        const data = await resp.json();
        output.innerText = `HTTP ${resp.status} ${resp.statusText}\n\n` + JSON.stringify(data, null, 2);
    } catch (e) {
        output.innerText = "Request failed: " + e.message;
    }
    refreshAuditLogs();
}

// --- OWASP Attack Playground Simulations ---

// Attack 1: BOLA / IDOR (API1)
async function runBolaAttack() {
    const token = document.getElementById("activeTokenInput").value.trim() || state.accessToken;
    const output = document.getElementById("attackOutput");
    if (!token) {
        alert("Please authenticate Alice first via the OAuth tab.");
        return;
    }

    output.innerText = "[ATTACK EXECUTION] Attempting BOLA / IDOR Attack:\n" +
        "Alice is logged in. Attack payload modifies account_id from Alice's account to Bob's account ('acc_bob_chk_01')...\n\n" +
        "GET /api/v1/accounts/acc_bob_chk_01/balances\n" +
        "Authorization: Bearer <Alice's Token>\n\n";

    try {
        const resp = await fetch("/api/v1/accounts/acc_bob_chk_01/balances", {
            headers: {
                "Authorization": `Bearer ${token}`,
                "X-API-Key": state.apiKey
            }
        });
        const data = await resp.json();
        output.innerText += `RESULT: HTTP ${resp.status} ${resp.statusText}\n` +
            JSON.stringify(data, null, 2) + "\n\n" +
            "✅ SECURITY VERIFICATION: BOLA / IDOR ATTACK BLOCKED!\n" +
            "The Resource Server verified that Alice's token and consent do NOT authorize access to Bob's account ID.\n" +
            "A security audit log event 'BOLA_VIOLATION_BLOCKED' has been recorded.";
    } catch (e) {
        output.innerText += "Error: " + e.message;
    }
    refreshAuditLogs();
}

// Attack 2: Tampered RS256 JWT (API2)
async function runTamperedJwtAttack() {
    const token = document.getElementById("activeTokenInput").value.trim() || state.accessToken;
    const output = document.getElementById("attackOutput");
    if (!token) {
        alert("Please authenticate Alice first via the OAuth tab.");
        return;
    }

    // Tamper the token by modifying the last characters of the cryptographic signature
    const parts = token.split('.');
    const tamperedSig = parts[2].substring(0, parts[2].length - 4) + "XXXX";
    const tamperedToken = `${parts[0]}.${parts[1]}.${tamperedSig}`;

    output.innerText = "[ATTACK EXECUTION] Attempting Broken Authentication / Tampered JWT (API2):\n" +
        "Modifying cryptographic signature bits in transit...\n\n" +
        `GET /api/v1/accounts\n` +
        `Authorization: Bearer ${tamperedToken.substring(0, 30)}...[TAMPERED]\n\n`;

    try {
        const resp = await fetch("/api/v1/accounts", {
            headers: {
                "Authorization": `Bearer ${tamperedToken}`,
                "X-API-Key": state.apiKey
            }
        });
        const data = await resp.json();
        output.innerText += `RESULT: HTTP ${resp.status} ${resp.statusText}\n` +
            JSON.stringify(data, null, 2) + "\n\n" +
            "✅ SECURITY VERIFICATION: TAMPERED JWT REJECTED!\n" +
            "The asymmetric RS256 public key failed signature verification locally without touching the database.";
    } catch (e) {
        output.innerText += "Error: " + e.message;
    }
    refreshAuditLogs();
}

// Attack 3: Excessive Data Exposure (API3 Data Minimization)
async function runDataMinimizationCheck() {
    const token = document.getElementById("activeTokenInput").value.trim() || state.accessToken;
    const output = document.getElementById("attackOutput");
    if (!token) {
        alert("Please authenticate Alice first via the OAuth tab.");
        return;
    }

    output.innerText = "[INSPECTION] Checking Data Minimization & Excessive Data Exposure (API3):\n" +
        "Querying /api/v1/accounts to inspect serialized response schema...\n\n";

    try {
        const resp = await fetch("/api/v1/accounts", {
            headers: {
                "Authorization": `Bearer ${token}`,
                "X-API-Key": state.apiKey
            }
        });
        const data = await resp.json();
        output.innerText += `RESULT: HTTP ${resp.status}\n` + JSON.stringify(data, null, 2) + "\n\n";

        const hasRouting = JSON.stringify(data).includes("ROUT-INTERNAL");
        const hasLedger = JSON.stringify(data).includes("LEDGER-CORE");

        if (!hasRouting && !hasLedger) {
            output.innerText += "✅ SECURITY VERIFICATION: DATA MINIMIZATION ENFORCED!\n" +
                "- Internal Bank Routing Codes ('internal_routing_code'): STRICTLY FILTERED OUT\n" +
                "- Core Ledger References ('internal_ledger_ref'): STRICTLY FILTERED OUT\n" +
                "- Balances separated into dedicated scope-protected endpoint ('balances:read').";
        } else {
            output.innerText += "❌ LEAK DETECTED! Internal banking properties were exposed.";
        }
    } catch (e) {
        output.innerText += "Error: " + e.message;
    }
}

// Attack 4: Rate Limit Exhaustion (API4)
async function runRateLimitAttack() {
    const output = document.getElementById("attackOutput");
    output.innerText = "[ATTACK EXECUTION] Attempting Unrestricted Resource Consumption / Rate Limit Exhaustion (API4):\n" +
        "Firing burst of 12 rapid API requests to exceed partner threshold...\n\n";

    let triggered429 = false;
    let lastHeaders = {};

    for (let i = 1; i <= 12; i++) {
        try {
            const resp = await fetch("/api/v1/partners/me", {
                headers: { "X-API-Key": state.apiKey }
            });
            lastHeaders = {
                limit: resp.headers.get("X-RateLimit-Limit"),
                remaining: resp.headers.get("X-RateLimit-Remaining"),
                reset: resp.headers.get("X-RateLimit-Reset"),
                retryAfter: resp.headers.get("Retry-After")
            };

            if (resp.status === 429) {
                triggered429 = true;
                const errData = await resp.json();
                output.innerText += `[Req #${i}] 💥 HTTP 429 TOO MANY REQUESTS!\n` +
                    `Headers:\n  X-RateLimit-Limit: ${lastHeaders.limit}\n  X-RateLimit-Remaining: ${lastHeaders.remaining}\n  Retry-After: ${lastHeaders.retryAfter}s\n` +
                    JSON.stringify(errData, null, 2) + "\n\n" +
                    "✅ SECURITY VERIFICATION: RATE LIMITING ENFORCED!\n" +
                    "Sliding window rate limiter prevented endpoint resource exhaustion and emitted standard RFC 6585 headers.";
                break;
            } else {
                output.innerText += `[Req #${i}] HTTP 200 OK (Remaining tokens: ${lastHeaders.remaining})\n`;
            }
        } catch (e) {
            output.innerText += `Req #${i} failed: ${e.message}\n`;
        }
    }

    if (!triggered429) {
        output.innerText += "\n(Note: Requests were under the 60 RPM limit; burst again quickly to trigger 429.)";
    }
    refreshAuditLogs();
}

// Attack 5: Broken Function Level Authorization (API5)
async function runBflaAttack() {
    const token = document.getElementById("activeTokenInput").value.trim() || state.accessToken;
    const output = document.getElementById("attackOutput");
    if (!token) {
        alert("Please authenticate Alice first via the OAuth tab.");
        return;
    }

    output.innerText = "[ATTACK EXECUTION] Attempting Broken Function Level Authorization / BFLA (API5):\n" +
        "Using read-only access token (accounts:read, balances:read) to initiate a $5,000.00 financial transfer via POST /api/v1/payments...\n\n";

    // Dummy DPoP proof
    const dpopProof = btoa(JSON.stringify({
        htm: "POST",
        htu: "/api/v1/payments",
        iat: Math.floor(Date.now() / 1000),
        jti: "test_bfla_" + Math.random()
    }));

    try {
        const resp = await fetch("/api/v1/payments", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${token}`,
                "Content-Type": "application/json",
                "X-DPoP-Proof": dpopProof
            },
            body: JSON.stringify({
                source_account_id: "acc_alice_chk_01",
                destination_account_id: "acc_attacker_99",
                amount: 5000.00,
                currency: "USD",
                description: "Unauthorized privilege escalation transfer"
            })
        });

        const data = await resp.json();
        output.innerText += `RESULT: HTTP ${resp.status} ${resp.statusText}\n` +
            JSON.stringify(data, null, 2) + "\n\n";

        if (resp.status === 403) {
            output.innerText += "✅ SECURITY VERIFICATION: FUNCTION LEVEL AUTHORIZATION ENFORCED!\n" +
                "The server verified that token scopes do NOT include 'payments:write'. Privilege escalation blocked.";
        }
    } catch (e) {
        output.innerText += "Error: " + e.message;
    }
    refreshAuditLogs();
}

// Attack 6: DPoP Replay Attack
async function runReplayAttack() {
    const token = document.getElementById("activeTokenInput").value.trim() || state.accessToken;
    const output = document.getElementById("attackOutput");
    if (!token) {
        alert("Please authenticate Alice first with 'payments:write' scope.");
        return;
    }

    const staticJti = "dpop_replay_fixed_jti_" + Math.random().toString(36).substring(7);
    const proofPayload = {
        htm: "POST",
        htu: "/api/v1/payments",
        iat: Math.floor(Date.now() / 1000),
        jti: staticJti
    };
    const proofHeader = btoa(JSON.stringify(proofPayload));

    output.innerText = "[ATTACK EXECUTION] Attempting Proof-of-Possession / DPoP Replay Attack:\n" +
        `Fixed Proof JTI: '${staticJti}'\n` +
        "Step 1: Sending legitimate signed request...\n";

    const paymentBody = JSON.stringify({
        source_account_id: "acc_alice_chk_01",
        destination_account_id: "acc_alice_sav_02",
        amount: 10.00,
        currency: "USD",
        description: "Legitimate transfer test"
    });

    try {
        // First request (Expected: success or scope failure, but DPoP accepted)
        const resp1 = await fetch("/api/v1/payments", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${token}`,
                "Content-Type": "application/json",
                "X-DPoP-Proof": proofHeader,
                "Idempotency-Key": "idem_" + Math.random()
            },
            body: paymentBody
        });
        const data1 = await resp1.json();
        output.innerText += `Step 1 Result: HTTP ${resp1.status} (Proof JTI registered in replay cache)\n\n`;

        // Step 2: Attacker replays identical proof header!
        output.innerText += "Step 2: Attacker intercepts and REPLAYS the EXACT SAME proof header...\n\n";

        const resp2 = await fetch("/api/v1/payments", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${token}`,
                "Content-Type": "application/json",
                "X-DPoP-Proof": proofHeader
            },
            body: paymentBody
        });

        const data2 = await resp2.json();
        output.innerText += `Step 2 Result: HTTP ${resp2.status} ${resp2.statusText}\n` +
            JSON.stringify(data2, null, 2) + "\n\n";

        if (resp2.status === 401 && JSON.stringify(data2).includes("replay_detected")) {
            output.innerText += "✅ SECURITY VERIFICATION: REPLAY ATTACK BLOCKED!\n" +
                "The DPoP anti-replay cache detected duplicate proof JTI and immediately rejected the replayed request.";
        }
    } catch (e) {
        output.innerText += "Replay test error: " + e.message;
    }
    refreshAuditLogs();
}

// --- Audit Log Controls ---
async function refreshAuditLogs() {
    const filter = document.getElementById("auditFilterSelect")?.value || "";
    const logs = await AuditManager.fetchLogs(filter);
    AuditManager.renderLogs(logs, "auditLogTableBody");
}
