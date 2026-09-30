"""Security Audit Logging with Automatic Sensitive Data Redaction."""
import logging
import re
from typing import Optional
from sqlalchemy.orm import Session
from app.models import AuditLog

logger = logging.getLogger("security.audit")
logger.setLevel(logging.INFO)

# Regex patterns to sanitize sensitive credentials from log details
REDACTION_PATTERNS = [
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"ob_live_[A-Za-z0-9_]+", re.IGNORECASE), "ob_live_[REDACTED_API_KEY]"),
    (re.compile(r'("password"\s*:\s*)"[^"]+"', re.IGNORECASE), r'\1"[REDACTED_PASSWORD]"'),
    (re.compile(r'("raw_api_key"\s*:\s*)"[^"]+"', re.IGNORECASE), r'\1"[REDACTED_KEY]"'),
    (re.compile(r'("code_verifier"\s*:\s*)"[^"]+"', re.IGNORECASE), r'\1"[REDACTED_VERIFIER]"'),
    (re.compile(r'\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b'), "[REDACTED_CARD_NUMBER]")
]


def sanitize_message(text: str) -> str:
    """Removes passwords, API keys, and JWT tokens from strings before logging."""
    if not text:
        return ""
    sanitized = text
    for pattern, replacement in REDACTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def log_security_event(
    db: Session,
    event_type: str,
    endpoint: str,
    method: str,
    ip_address: str,
    status_code: int,
    details: str,
    client_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    account_id: Optional[str] = None
) -> AuditLog:
    """
    Persists a sanitized security audit event to the database and standard logging.
    Ensures zero confidential credentials leak into logs.
    """
    clean_details = sanitize_message(details)

    log_entry = AuditLog(
        event_type=event_type,
        client_id=client_id,
        customer_id=customer_id,
        account_id=account_id,
        endpoint=endpoint,
        method=method.upper(),
        ip_address=ip_address,
        status_code=status_code,
        details=clean_details
    )

    try:
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to persist audit log: {e}")

    logger.info(
        f"[{event_type}] {method.upper()} {endpoint} status={status_code} "
        f"client={client_id} customer={customer_id} account={account_id} - {clean_details}"
    )

    return log_entry
