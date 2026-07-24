"""
Password sanitization utilities.
All password data must pass through sanitize_password() immediately upon receipt from APIs.
The original plaintext is NEVER stored — only passed transiently to ROPC if enabled.
"""

import re


def sanitize_password(password) -> dict:
    """
    Sanitize a password field immediately upon receipt.

    Returns a dict with:
        present     : bool   — was a password field present?
        masked      : str    — safe version for logging/storage (default behavior)
        is_plaintext: bool   — is this an unmasked credential?
        _raw        : str    — INTERNAL USE ONLY for ROPC. Caller must del after use.
    """
    if not password or not str(password).strip():
        return {"present": False, "masked": None, "is_plaintext": False, "_raw": None}

    pw = str(password).strip()

    # API may already return masked values like "a****3" or "S****#"
    is_masked = bool(re.search(r"\*{2,}", pw))

    if is_masked:
        masked = pw
    else:
        # Build a masked version: first char + *** + last char
        if len(pw) >= 2:
            masked = f"{pw[0]}***{pw[-1]}"
        else:
            masked = "***"

    return {
        "present": True,
        "masked": masked,
        "is_plaintext": not is_masked,
        "_raw": pw,          # ROPC callers: use this, then immediately `del result["_raw"]`
    }


def build_law_password_fields(sanitized: dict, enable_log_plaintext: bool) -> dict:
    """
    Build the password-related fields to write to Log Analytics.

    Args:
        sanitized           : output of sanitize_password()
        enable_log_plaintext: if True, include the raw value (customer's choice)

    Returns dict to merge into the LAW record.
    """
    fields = {
        "password_present": sanitized["present"],
        "password_masked":  sanitized.get("masked"),
        "is_plaintext":     sanitized.get("is_plaintext", False),
    }
    if enable_log_plaintext and sanitized.get("_raw"):
        fields["password"] = sanitized["_raw"]
    return fields
