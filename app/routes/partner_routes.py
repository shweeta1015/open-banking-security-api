"""Partner Management API Routes."""
from typing import List
from fastapi import APIRouter, Depends, Request, status, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Partner
from app.schemas import (
    PartnerRegisterRequest,
    PartnerCreatedResponse,
    PartnerResponse,
    ApiKeyRotateResponse
)
from app.security.api_key import get_api_key_partner
from app.security.rate_limiter import enforce_rate_limit
from app.security.audit import log_security_event
from app.services.partner_service import PartnerService

router = APIRouter(prefix="/api/v1/partners", tags=["Partners & API Keys"])


@router.post("/register", response_model=PartnerCreatedResponse, status_code=status.HTTP_201_CREATED)
def register_partner(
    req: PartnerRegisterRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Register a new fintech partner organization.
    Issues a cryptographically secure API key.
    SECURITY NOTICE: The raw API key is returned ONLY ONCE upon registration and never stored in plain text.
    """
    partner, raw_key = PartnerService.register_partner(db, req)
    client_ip = request.client.host if request.client else "127.0.0.1"

    log_security_event(
        db=db,
        event_type="PARTNER_REGISTERED",
        client_id=partner.client_id,
        endpoint=request.url.path,
        method=request.method,
        ip_address=client_ip,
        status_code=201,
        details=f"Partner registered: '{partner.name}' (Prefix: {partner.api_key_prefix})"
    )

    return PartnerCreatedResponse(
        client_id=partner.client_id,
        name=partner.name,
        api_key_prefix=partner.api_key_prefix,
        redirect_uris=partner.get_redirect_uris(),
        rate_limit_rpm=partner.rate_limit_rpm,
        status=partner.status,
        created_at=partner.created_at,
        raw_api_key=raw_key
    )


@router.get("/me", response_model=PartnerResponse)
def get_current_partner_profile(
    request: Request,
    partner: Partner = Depends(get_api_key_partner),
    _limiter = Depends(enforce_rate_limit)
):
    """
    Returns the authenticated partner's profile using the X-API-Key header.
    Shows key prefix and status without leaking secret hash.
    """
    return PartnerResponse(
        client_id=partner.client_id,
        name=partner.name,
        api_key_prefix=partner.api_key_prefix,
        redirect_uris=partner.get_redirect_uris(),
        rate_limit_rpm=partner.rate_limit_rpm,
        status=partner.status,
        created_at=partner.created_at
    )


@router.post("/{client_id}/rotate-key", response_model=ApiKeyRotateResponse)
def rotate_api_key(
    client_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Rotates the API key for a registered partner.
    The previous key hash is replaced immediately.
    """
    partner, new_key = PartnerService.rotate_api_key(db, client_id)
    client_ip = request.client.host if request.client else "127.0.0.1"

    log_security_event(
        db=db,
        event_type="API_KEY_ROTATED",
        client_id=client_id,
        endpoint=request.url.path,
        method=request.method,
        ip_address=client_ip,
        status_code=200,
        details=f"API Key successfully rotated for partner '{client_id}'. New prefix: {partner.api_key_prefix}"
    )

    return ApiKeyRotateResponse(
        client_id=partner.client_id,
        new_api_key_prefix=partner.api_key_prefix,
        raw_api_key=new_key
    )


@router.post("/{client_id}/revoke")
def revoke_partner(
    client_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Revokes partner credentials. Further requests will receive HTTP 403 Forbidden.
    """
    partner = PartnerService.revoke_partner(db, client_id)
    client_ip = request.client.host if request.client else "127.0.0.1"

    log_security_event(
        db=db,
        event_type="PARTNER_REVOKED",
        client_id=client_id,
        endpoint=request.url.path,
        method=request.method,
        ip_address=client_ip,
        status_code=200,
        details=f"Partner '{client_id}' access revoked."
    )

    return {"message": f"Partner '{client_id}' has been revoked.", "status": partner.status}


@router.get("", response_model=List[PartnerResponse])
def list_partners(
    db: Session = Depends(get_db)
):
    """Lists registered partners (for educational simulator dashboard)."""
    partners = db.query(Partner).all()
    return [
        PartnerResponse(
            client_id=p.client_id,
            name=p.name,
            api_key_prefix=p.api_key_prefix,
            redirect_uris=p.get_redirect_uris(),
            rate_limit_rpm=p.rate_limit_rpm,
            status=p.status,
            created_at=p.created_at
        )
        for p in partners
    ]
