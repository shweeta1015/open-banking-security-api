"""Replay Protection: DPoP-Style Proof-of-Possession and Idempotency Control.

EDUCATIONAL CONTEXT:
Why plain Bearer JWTs cannot prevent replay attacks:
Bearer tokens operate like physical cash: whoever possesses the token can present it
and obtain service. If an attacker intercepts a bearer token (via an insecure proxy,
TLS interception, browser cache, or server-side logging), the attacker can replay
the token to access victim resources until the token reaches its 'exp' time.

DPoP (Demonstrating Proof-of-Possession - RFC 9449) Solution:
1. Client generates a unique proof on EVERY request containing:
   - 'htm': HTTP method (e.g. GET, POST)
   - 'htu': HTTP target URI path (e.g. /api/v1/accounts)
   - 'iat': Issued-at timestamp (valid only for a very tight window, e.g. 60 seconds)
   - 'jti': Unique proof identifier (UUID)
2. Resource server validates:
   - Freshness: Reject if timestamp is older than 60s or in the future
   - Method & Path: Reject if replayed against another endpoint
   - Uniqueness (Replay Cache): The 'jti' is recorded in a short-lived TTL cache.
     If the same 'jti' is presented a second time, the request is REJECTED WITH 401.
"""
from datetime import datetime, timezone
import json
import base64
import time
import threading
from typing import Dict, Any, Optional
from fastapi import Request, HTTPException, status
from app.config import get_settings

settings = get_settings()


class ReplayCache:
    """Thread-safe in-memory TTL cache for proof-of-possession JTIs."""
    def __init__(self, ttl_seconds: int = 120):
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _purge_expired(self, now: float) -> None:
        expired_keys = [k for k, exp in self._cache.items() if exp < now]
        for k in expired_keys:
            del self._cache[k]

    def check_and_add(self, jti: str) -> bool:
        """
        Returns True if JTI is fresh and newly added.
        Returns False if JTI was already seen (replay detected!).
        """
        now = time.time()
        with self._lock:
            self._purge_expired(now)
            if jti in self._cache:
                return False  # REPLAY DETECTED!
            self._cache[jti] = now + self.ttl_seconds
            return True


# Global replay cache instance
replay_cache = ReplayCache(ttl_seconds=settings.DPOP_PROOF_MAX_AGE_SECONDS * 2)


def create_demo_dpop_proof(method: str, path: str, jti: Optional[str] = None) -> str:
    """
    Helper function to construct a base64-encoded DPoP demonstration proof.
    Used by test client and frontend simulator.
    """
    import uuid
    proof_data = {
        "htm": method.upper(),
        "htu": path,
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "jti": jti or str(uuid.uuid4())
    }
    raw_json = json.dumps(proof_data)
    return base64.urlsafe_b64encode(raw_json.encode("utf-8")).decode("utf-8")


def validate_dpop_proof(request: Request) -> Dict[str, Any]:
    """
    Validates DPoP / Proof-of-Possession header (X-DPoP-Proof or DPoP).
    Enforces freshness, method match, URI match, and anti-replay via JTI cache.
    """
    proof_header = request.headers.get("X-DPoP-Proof") or request.headers.get("DPoP")
    if not proof_header:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "missing_dpop_proof",
                "error_description": "Sensitive endpoint requires proof-of-possession in 'X-DPoP-Proof' header."
            }
        )

    # Decode JSON or base64url payload
    try:
        if proof_header.startswith("{"):
            payload = json.loads(proof_header)
        else:
            padded = proof_header + "=" * ((4 - len(proof_header) % 4) % 4)
            decoded_bytes = base64.urlsafe_b64decode(padded)
            payload = json.loads(decoded_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_dpop_proof", "error_description": "Unable to parse DPoP proof payload."}
        )

    required_fields = ["htm", "htu", "iat", "jti"]
    for field in required_fields:
        if field not in payload:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_dpop_proof", "error_description": f"Missing required proof field '{field}'"}
            )

    # 1. Freshness check (within max age window)
    now_ts = int(datetime.now(timezone.utc).timestamp())
    proof_iat = int(payload["iat"])
    skew = abs(now_ts - proof_iat)
    if skew > settings.DPOP_PROOF_MAX_AGE_SECONDS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "expired_dpop_proof",
                "error_description": f"Proof timestamp is too old or skewed (drift: {skew}s, max allowed: {settings.DPOP_PROOF_MAX_AGE_SECONDS}s)"
            }
        )

    # 2. HTTP Method match
    expected_method = request.method.upper()
    if payload["htm"].upper() != expected_method:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_dpop_proof",
                "error_description": f"Proof method mismatch: proof says '{payload['htm']}', actual is '{expected_method}'"
            }
        )

    # 3. HTTP Target URI path match
    expected_path = request.url.path
    if payload["htu"] != expected_path:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_dpop_proof",
                "error_description": f"Proof target URI mismatch: proof says '{payload['htu']}', actual is '{expected_path}'"
            }
        )

    # 4. Anti-Replay Cache check
    jti = str(payload["jti"])
    is_fresh = replay_cache.check_and_add(jti)
    if not is_fresh:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "replay_detected",
                "error_description": f"SECURITY ALERT: Replay attack detected! Proof JTI '{jti}' has already been presented and consumed."
            }
        )

    return payload
