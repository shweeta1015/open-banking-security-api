"""Protected Open Banking API Routes with BOLA, Data Minimization, and Replay Protection."""
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, Request, status, HTTPException, Header
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas import (
    AccountSummary,
    BalanceResponse,
    TransactionResponse,
    PaymentInitiateRequest,
    PaymentInitiateResponse
)
from app.security.jwt_handler import get_current_token_claims, require_scope
from app.security.rate_limiter import enforce_rate_limit
from app.security.dpop import validate_dpop_proof
from app.security.audit import log_security_event
from app.services.banking_service import BankingService

router = APIRouter(prefix="/api/v1", tags=["Open Banking APIs"])


@router.get("/accounts", response_model=List[AccountSummary])
def list_accounts(
    request: Request,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(require_scope("accounts:read")),
    _rate_limit = Depends(enforce_rate_limit)
):
    """
    List Authorized Accounts for Consented Customer.
    SECURITY CONTROLS:
    - Token validated using local RSA public key (zero DB query).
    - Requires 'accounts:read' scope.
    - Data Minimization: Excludes account balances and internal bank routing codes.
    - Audits access.
    """
    customer_id = claims["sub"]
    consent_id = claims["consent_id"]
    client_ip = request.client.host if request.client else "127.0.0.1"

    accounts = BankingService.get_authorized_accounts(
        db=db,
        customer_id=customer_id,
        consent_id=consent_id
    )

    log_security_event(
        db=db,
        event_type="SENSITIVE_API_ACCESS",
        client_id=claims.get("client_id"),
        customer_id=customer_id,
        endpoint=request.url.path,
        method=request.method,
        ip_address=client_ip,
        status_code=200,
        details=f"Retrieved {len(accounts)} consented accounts for customer '{customer_id}'"
    )

    return accounts


@router.get("/accounts/{account_id}", response_model=AccountSummary)
def get_account(
    account_id: str,
    request: Request,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(require_scope("accounts:read")),
    _rate_limit = Depends(enforce_rate_limit)
):
    """
    Retrieve Account Summary.
    SECURITY CONTROLS:
    - API1 BOLA Protection: Validates that the requested account_id is owned by token's customer
      AND authorized in active consent.
    - Rejects unauthorized cross-customer account queries with safe 404/403.
    """
    customer_id = claims["sub"]
    consent_id = claims["consent_id"]
    client_ip = request.client.host if request.client else "127.0.0.1"

    try:
        account = BankingService.get_account_detail(
            db=db,
            customer_id=customer_id,
            consent_id=consent_id,
            account_id=account_id
        )
        return account
    except HTTPException as e:
        log_security_event(
            db=db,
            event_type="BOLA_VIOLATION_BLOCKED",
            client_id=claims.get("client_id"),
            customer_id=customer_id,
            account_id=account_id,
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=e.status_code,
            details=f"BOLA/IDOR attempt blocked for account '{account_id}': {e.detail}"
        )
        raise e


@router.get("/accounts/{account_id}/balances", response_model=BalanceResponse)
def get_account_balance(
    account_id: str,
    request: Request,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(require_scope("balances:read")),
    _rate_limit = Depends(enforce_rate_limit)
):
    """
    Retrieve Account Balance.
    SECURITY CONTROLS:
    - Requires distinct 'balances:read' scope (Data Minimization / Separation of Duties).
    - API1 BOLA check on account_id.
    """
    customer_id = claims["sub"]
    consent_id = claims["consent_id"]
    client_ip = request.client.host if request.client else "127.0.0.1"

    try:
        balance_info = BankingService.get_account_balance(
            db=db,
            customer_id=customer_id,
            consent_id=consent_id,
            account_id=account_id
        )
        log_security_event(
            db=db,
            event_type="SENSITIVE_API_ACCESS",
            client_id=claims.get("client_id"),
            customer_id=customer_id,
            account_id=account_id,
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=200,
            details=f"Balance accessed for account '{account_id}'"
        )
        return balance_info
    except HTTPException as e:
        log_security_event(
            db=db,
            event_type="BOLA_VIOLATION_BLOCKED",
            client_id=claims.get("client_id"),
            customer_id=customer_id,
            account_id=account_id,
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=e.status_code,
            details=f"Unauthorized balance query blocked: {e.detail}"
        )
        raise e


@router.get("/accounts/{account_id}/transactions", response_model=List[TransactionResponse])
def get_account_transactions(
    account_id: str,
    request: Request,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(require_scope("transactions:read")),
    _rate_limit = Depends(enforce_rate_limit)
):
    """
    Retrieve Account Transactions.
    SECURITY CONTROLS:
    - Requires 'transactions:read' scope.
    - API1 BOLA check on account_id.
    - Data Minimization: Excludes internal bank core ledger references.
    """
    customer_id = claims["sub"]
    consent_id = claims["consent_id"]
    client_ip = request.client.host if request.client else "127.0.0.1"

    try:
        txs = BankingService.get_account_transactions(
            db=db,
            customer_id=customer_id,
            consent_id=consent_id,
            account_id=account_id
        )
        log_security_event(
            db=db,
            event_type="SENSITIVE_API_ACCESS",
            client_id=claims.get("client_id"),
            customer_id=customer_id,
            account_id=account_id,
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=200,
            details=f"Retrieved {len(txs)} transactions for account '{account_id}'"
        )
        return txs
    except HTTPException as e:
        log_security_event(
            db=db,
            event_type="BOLA_VIOLATION_BLOCKED",
            client_id=claims.get("client_id"),
            customer_id=customer_id,
            account_id=account_id,
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=e.status_code,
            details=f"Unauthorized transactions query blocked: {e.detail}"
        )
        raise e


@router.post("/payments", response_model=PaymentInitiateResponse, status_code=status.HTTP_201_CREATED)
def initiate_payment(
    req: PaymentInitiateRequest,
    request: Request,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(require_scope("payments:write")),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    _rate_limit = Depends(enforce_rate_limit)
):
    """
    Initiate Simulated Financial Payment.
    SECURITY CONTROLS:
    - API5 BFLA Protection: Requires 'payments:write' scope (read-only tokens are rejected).
    - API1 BOLA Protection: Source account must belong to token's customer and have explicit consent.
    - Replay Prevention: Requires valid DPoP proof in 'X-DPoP-Proof' header. Replayed proofs are blocked.
    - Idempotency Protection: Re-submitting with identical 'Idempotency-Key' returns cached result without double-charging.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Validate DPoP proof-of-possession & anti-replay cache
    try:
        validate_dpop_proof(request)
    except HTTPException as e:
        log_security_event(
            db=db,
            event_type="REPLAY_ATTACK_BLOCKED" if "replay" in str(e.detail) else "SECURITY_VIOLATION",
            client_id=claims.get("client_id"),
            customer_id=claims.get("sub"),
            account_id=req.source_account_id,
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=e.status_code,
            details=f"Payment rejected by DPoP/Replay protection: {e.detail}"
        )
        raise e

    try:
        payment = BankingService.process_payment(
            db=db,
            customer_id=claims["sub"],
            consent_id=claims["consent_id"],
            client_id=claims.get("client_id", "unknown"),
            req=req,
            idempotency_key=idempotency_key
        )

        log_security_event(
            db=db,
            event_type="PAYMENT_EXECUTED",
            client_id=claims.get("client_id"),
            customer_id=claims["sub"],
            account_id=req.source_account_id,
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=201,
            details=f"Payment initiated: {payment.amount} {payment.currency} from {payment.source_account_id} to {payment.destination_account_id}"
        )
        return payment
    except HTTPException as e:
        log_security_event(
            db=db,
            event_type="PAYMENT_FAILED",
            client_id=claims.get("client_id"),
            customer_id=claims.get("sub"),
            account_id=req.source_account_id,
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=e.status_code,
            details=f"Payment execution failed: {e.detail}"
        )
        raise e
