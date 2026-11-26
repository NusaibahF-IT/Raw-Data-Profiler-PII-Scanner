"""Owner access guard for Public Demo + Owner-Only Upload mode."""
from __future__ import annotations

import hmac
import os
from typing import Dict, Optional

from fastapi import Header, HTTPException


def is_upload_locked() -> bool:
    """Lock public uploads on Vercel or whenever OWNER_ACCESS_CODE is configured."""
    on_vercel = bool(os.environ.get("VERCEL") or os.environ.get("VERCEL_ENV"))
    configured_code = os.environ.get("OWNER_ACCESS_CODE", "").strip()
    return on_vercel or bool(configured_code)


def get_access_status() -> Dict[str, bool]:
    configured_code = os.environ.get("OWNER_ACCESS_CODE", "").strip()
    return {
        "upload_locked": is_upload_locked(),
        "owner_code_configured": bool(configured_code),
    }


def verify_owner_code(provided_code: Optional[str]) -> None:
    """Verify X-Owner-Code header when upload lock is active."""
    if not is_upload_locked():
        return
    expected = os.environ.get("OWNER_ACCESS_CODE", "").strip()
    if not expected:
        raise HTTPException(
            status_code=403,
            detail="Public Demo Mode: uploads are locked because OWNER_ACCESS_CODE is not configured.",
        )
    if not provided_code or not hmac.compare_digest(provided_code.strip(), expected):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing Owner Access Code.",
        )


def require_owner_upload(x_owner_code: Optional[str] = Header(default=None)) -> None:
    verify_owner_code(x_owner_code)
