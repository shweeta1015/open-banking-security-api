"""OAuth 2.0 Authorization Server Service with PKCE and Consent."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
from typing import Tuple, List, Dict, Any
from urllib.parse import urlencode
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.config import get_settings
from app.models import Partner, Customer, Account, Consent, AuthorizationCode
from app.schemas import ConsentSubmitRequest, TokenRequest, TokenResponse
from app.security.crypto import verify_secret
from app.security.pkce import verify_pkce
from app.security.jwt_handler import issue_access_token

settings = get_settings()


class OAuthService:
    @staticmethod
    def validate_client_and_redirect(
        db: Session,
        client_id: str,
        redirect_uri: str
    ) -> Partner:
        """Validates partner registration and registered redirect URI."""
        partner = db.query(Partner).filter(Partner.client_id == client_id).first()
        if not partner:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_client", "error_description": f"Client '{client_id}' is not registered."}
            )

        if partner.status != "ACTIVE":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "unauthorized_client", "error_description": "Partner has been revoked."}
            )

        allowed_uris = partner.get_redirect_uris()
        if redirect_uri not in allowed_uris:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "invalid_redirect_uri",
                    "error_description": f"Redirect URI '{redirect_uri}' is not registered for client '{client_id}'."
                }
            )

        return partner

    @staticmethod
    def authenticate_customer(
        db: Session,
        username: str,
        password: str
    ) -> Customer:
        """Authenticates bank customer credentials."""
        customer = db.query(Customer).filter(Customer.username == username).first()
        if not customer or not verify_secret(password, customer.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "invalid_credentials", "error_description": "Invalid customer username or password."}
            )
        return customer

    @staticmethod
    def process_consent_and_grant_code(
        db: Session,
        req: ConsentSubmitRequest
    ) -> Tuple[str, str]:
        """
        Processes customer login & consent selection.
        Validates accounts belong to customer, creates Consent record, and issues PKCE-bound Authorization Code.
        Returns: (raw_auth_code, full_redirect_url)
        """
        # 1. Validate partner and redirect URI
        OAuthService.validate_client_and_redirect(db, req.client_id, req.redirect_uri)

        # 2. Authenticate customer
        customer = OAuthService.authenticate_customer(db, req.username, req.password)

        # 3. Validate requested accounts strictly belong to this authenticated customer (BOLA prevention during consent!)
        customer_accounts = db.query(Account).filter(Account.customer_id == customer.customer_id).all()
        valid_account_ids = {acc.account_id for acc in customer_accounts}

        for acc_id in req.allowed_account_ids:
            if acc_id not in valid_account_ids:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "access_denied",
                        "error_description": f"Cannot grant consent for account '{acc_id}' not owned by customer."
                    }
                )

        # 4. Create Consent Record
        now = datetime.now(timezone.utc)
        consent_id = f"consent_{secrets.token_hex(12)}"
        consent = Consent(
            consent_id=consent_id,
            client_id=req.client_id,
            customer_id=customer.customer_id,
            allowed_account_ids=json.dumps(req.allowed_account_ids),
            scopes=" ".join(req.scopes),
            status="ACTIVE",
            created_at=now,
            expires_at=now + timedelta(days=90)
        )
        db.add(consent)

        # 5. Issue Single-Use Authorization Code
        raw_code = f"authcode_{secrets.token_urlsafe(32)}"
        code_hash = hashlib.sha256(raw_code.encode("utf-8")).hexdigest()

        auth_code_record = AuthorizationCode(
            code_hash=code_hash,
            client_id=req.client_id,
            customer_id=customer.customer_id,
            consent_id=consent_id,
            redirect_uri=req.redirect_uri,
            code_challenge=req.code_challenge,
            code_challenge_method=req.code_challenge_method,
            scopes=" ".join(req.scopes),
            used=False,
            created_at=now,
            expires_at=now + timedelta(seconds=settings.AUTH_CODE_EXPIRE_SECONDS)
        )
        db.add(auth_code_record)
        db.commit()

        # Build redirection query
        params = {
            "code": raw_code,
            "state": req.state
        }
        redirect_url = f"{req.redirect_uri}?{urlencode(params)}"
        return raw_code, redirect_url

    @staticmethod
    def exchange_code_for_token(
        db: Session,
        req: TokenRequest
    ) -> TokenResponse:
        """
        Exchanges Authorization Code + PKCE code_verifier for an RS256 JWT access token.
        Enforces single-use code semantics, expiration check, and S256 PKCE verification.
        """
        # Look up authorization code by SHA256 hash
        code_hash = hashlib.sha256(req.code.encode("utf-8")).hexdigest()
        auth_code = db.query(AuthorizationCode).filter(AuthorizationCode.code_hash == code_hash).first()

        if not auth_code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_grant", "error_description": "Authorization code is invalid or unknown."}
            )

        # Check if already used (re-play protection on auth codes)
        if auth_code.used:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_grant", "error_description": "Authorization code has already been used."}
            )

        # Mark code as consumed immediately
        auth_code.used = True
        db.commit()

        # Check code expiration
        now = datetime.now(timezone.utc)
        expires_at_utc = auth_code.expires_at.replace(tzinfo=timezone.utc) if auth_code.expires_at.tzinfo is None else auth_code.expires_at
        if now > expires_at_utc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_grant", "error_description": "Authorization code has expired."}
            )

        # Verify client_id matches
        if auth_code.client_id != req.client_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_grant", "error_description": "Client ID mismatch."}
            )

        # Verify redirect_uri matches
        if auth_code.redirect_uri != req.redirect_uri:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_grant", "error_description": "Redirect URI mismatch."}
            )

        # Verify PKCE S256 code_verifier
        pkce_valid = verify_pkce(
            code_verifier=req.code_verifier,
            code_challenge=auth_code.code_challenge,
            method=auth_code.code_challenge_method
        )
        if not pkce_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_grant", "error_description": "PKCE code_verifier validation failed."}
            )

        # Issue RS256 JWT Access Token
        scopes_list = auth_code.scopes.split(" ")
        access_token, expires_in = issue_access_token(
            customer_id=auth_code.customer_id,
            client_id=auth_code.client_id,
            consent_id=auth_code.consent_id,
            scopes=scopes_list
        )

        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            scope=auth_code.scopes,
            consent_id=auth_code.consent_id
        )
