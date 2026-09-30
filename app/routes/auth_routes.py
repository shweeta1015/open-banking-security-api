"""OAuth 2.0 PKCE, JWKS, and Consent Routes."""
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, Request, status, HTTPException, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Customer, Account, Consent
from app.schemas import (
    ConsentSubmitRequest,
    TokenRequest,
    TokenResponse,
    ConsentResponse
)
from app.security.crypto import get_jwks
from app.security.audit import log_security_event
from app.services.oauth_service import OAuthService

router = APIRouter(tags=["OAuth 2.0 & JWKS"])


@router.get("/.well-known/jwks.json")
def get_public_jwks():
    """
    RFC 7517 JSON Web Key Set (JWKS) endpoint.
    Exposes ONLY the public RSA key used to verify RS256 JWT signatures.
    Private keys remain strictly confidential on the authorization server.
    """
    return get_jwks()


@router.get("/oauth/authorize")
def authorize_endpoint(
    client_id: str = Query(..., description="Registered partner client ID"),
    response_type: str = Query("code", description="Must be 'code' for Authorization Code Flow"),
    redirect_uri: str = Query(..., description="Registered partner redirect URI"),
    scope: str = Query(..., description="Space-separated scopes, e.g. accounts:read balances:read"),
    state: str = Query(..., description="Opaque value to prevent CSRF"),
    code_challenge: str = Query(..., description="PKCE SHA-256 challenge string"),
    code_challenge_method: str = Query("S256", description="PKCE method (only S256 allowed)"),
    db: Session = Depends(get_db)
):
    """
    OAuth 2.0 Authorization Endpoint (RFC 6749 + RFC 7636 PKCE).
    Validates parameters and returns authorization session state for the consent screen.
    """
    if response_type != "code":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "unsupported_response_type", "error_description": "Only 'code' response_type is supported."}
        )

    if code_challenge_method != "S256":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_request", "error_description": "PKCE code_challenge_method must be 'S256'."}
        )

    # Validate partner registration and redirect URI registration
    partner = OAuthService.validate_client_and_redirect(db, client_id, redirect_uri)

    return {
        "status": "pending_consent",
        "client_id": partner.client_id,
        "client_name": partner.name,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method
    }


@router.post("/oauth/consent")
def submit_consent(
    req: ConsentSubmitRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Submits user authentication and explicit resource delegation.
    Demonstrates that partner API keys NEVER substitute for explicit user consent.
    Issues a single-use Authorization Code bound to the PKCE challenge.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"

    try:
        raw_code, redirect_url = OAuthService.process_consent_and_grant_code(db, req)

        log_security_event(
            db=db,
            event_type="CONSENT_GRANTED",
            client_id=req.client_id,
            customer_id=req.username,
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=200,
            details=f"Consent granted for accounts: {req.allowed_account_ids}, scopes: {req.scopes}"
        )

        return {
            "status": "approved",
            "code": raw_code,
            "state": req.state,
            "redirect_url": redirect_url
        }
    except HTTPException as e:
        log_security_event(
            db=db,
            event_type="AUTH_FAILURE",
            client_id=req.client_id,
            customer_id=req.username,
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=e.status_code,
            details=f"Consent rejected: {e.detail}"
        )
        raise e


@router.post("/oauth/token", response_model=TokenResponse)
def token_endpoint(
    req: TokenRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Exchanges Authorization Code + PKCE code_verifier for an RS256 JWT access token.
    Enforces single-use code semantics and S256 PKCE verification.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"

    try:
        token_resp = OAuthService.exchange_code_for_token(db, req)

        log_security_event(
            db=db,
            event_type="TOKEN_ISSUED",
            client_id=req.client_id,
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=200,
            details=f"RS256 JWT access token issued for consent '{token_resp.consent_id}'"
        )

        return token_resp
    except HTTPException as e:
        log_security_event(
            db=db,
            event_type="TOKEN_EXCHANGE_FAILURE",
            client_id=req.client_id,
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=e.status_code,
            details=f"Token exchange failed: {e.detail}"
        )
        raise e


@router.post("/oauth/revoke")
def revoke_consent(
    consent_id: str = Query(..., description="ID of consent to revoke"),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """
    Revokes customer consent.
    EDUCATIONAL NOTE ON JWT REVOCATION:
    While JWT signature and claims are verified stately using the public key,
    immediate revocation is implemented by marking the consent record status as 'REVOKED'.
    When the resource server checks consent status for high-value operations or token refresh,
    it honors this revocation.
    """
    consent = db.query(Consent).filter(Consent.consent_id == consent_id).first()
    if not consent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "consent_not_found", "error_description": "Consent ID not found."}
        )

    consent.status = "REVOKED"
    db.commit()

    client_ip = request.client.host if request and request.client else "127.0.0.1"
    log_security_event(
        db=db,
        event_type="CONSENT_REVOKED",
        client_id=consent.client_id,
        customer_id=consent.customer_id,
        endpoint="/oauth/revoke",
        method="POST",
        ip_address=client_ip,
        status_code=200,
        details=f"Consent '{consent_id}' has been revoked."
    )

    return {"message": f"Consent '{consent_id}' revoked successfully.", "status": "REVOKED"}


@router.get("/oauth/demo-customers")
def get_demo_customers(db: Session = Depends(get_db)):
    """
    Helper endpoint for the educational dashboard.
    Lists demo customers and their accounts to make testing and demonstration frictionless.
    """
    customers = db.query(Customer).all()
    results = []
    for c in customers:
        accs = [
            {
                "account_id": a.account_id,
                "account_number_masked": a.account_number_masked,
                "account_type": a.account_type,
                "currency": a.currency,
                "balance": a.balance
            }
            for a in c.accounts
        ]
        results.append({
            "customer_id": c.customer_id,
            "username": c.username,
            "full_name": c.full_name,
            "email": c.email,
            "accounts": accs
        })
    return results
