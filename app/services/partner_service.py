"""Partner Management Service."""
import json
from typing import Tuple, List, Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.models import Partner
from app.schemas import PartnerRegisterRequest
from app.security.api_key import generate_partner_api_key


class PartnerService:
    @staticmethod
    def register_partner(
        db: Session,
        req: PartnerRegisterRequest
    ) -> Tuple[Partner, str]:
        """Registers a new fintech partner and returns (partner, raw_api_key)."""
        existing = db.query(Partner).filter(Partner.client_id == req.client_id).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "partner_already_exists", "error_description": f"Partner '{req.client_id}' is already registered."}
            )

        raw_key, prefix, key_hash = generate_partner_api_key()
        partner = Partner(
            client_id=req.client_id,
            name=req.name,
            api_key_hash=key_hash,
            api_key_prefix=prefix,
            redirect_uris=json.dumps(req.redirect_uris),
            rate_limit_rpm=req.rate_limit_rpm or 60,
            status="ACTIVE"
        )
        db.add(partner)
        db.commit()
        db.refresh(partner)
        return partner, raw_key

    @staticmethod
    def rotate_api_key(
        db: Session,
        client_id: str
    ) -> Tuple[Partner, str]:
        """Rotates the partner's API key. Old key is immediately invalidated."""
        partner = db.query(Partner).filter(Partner.client_id == client_id).first()
        if not partner:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "partner_not_found", "error_description": f"Partner '{client_id}' not found."}
            )

        raw_key, prefix, key_hash = generate_partner_api_key()
        partner.api_key_prefix = prefix
        partner.api_key_hash = key_hash
        db.commit()
        db.refresh(partner)
        return partner, raw_key

    @staticmethod
    def revoke_partner(
        db: Session,
        client_id: str
    ) -> Partner:
        """Revokes a partner's access immediately."""
        partner = db.query(Partner).filter(Partner.client_id == client_id).first()
        if not partner:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "partner_not_found", "error_description": f"Partner '{client_id}' not found."}
            )
        partner.status = "REVOKED"
        db.commit()
        db.refresh(partner)
        return partner

    @staticmethod
    def get_partner(
        db: Session,
        client_id: str
    ) -> Optional[Partner]:
        return db.query(Partner).filter(Partner.client_id == client_id).first()
