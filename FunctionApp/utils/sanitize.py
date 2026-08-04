"""
Password sanitization utilities.
All password data must pass through sanitize_password() immediately upon receipt from APIs.

This module does not hide the credential. The value reaches Log Analytics exactly
as the feed delivered it, masked or clear, and the table declares a column for
it (docs/product-policy.md §2). What it adds is a locally derived
`password_masked`, so a dashboard has something safe to show.
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

    # The feed may already return a masked value like "a****3". Deciding that on
    # "contains two stars" alone treats a real password such as "Yaz**2026!" as
    # already masked — so require the stars to make up a large part of the value.
    stars = pw.count("*")
    is_masked = stars >= 2 and stars >= len(pw) * 0.25

    # Never store the value we were given, masked or not: build our own. A feed
    # that mislabels a plaintext password must not put it in Log Analytics.
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


def build_law_password_fields(sanitized: dict) -> dict:
    """
    Build the password-related fields to write to Log Analytics.

    The credential is stored as the feed delivered it. Whether a password
    arrives in the clear or already masked is decided in the SOCRadar platform,
    per company; a customer who does not want cleartext leaving SOCRadar never
    has it sent here in the first place. Adding a second switch on this side
    only meant the record could disagree with the source it came from.

    `password_masked` is still derived locally so a dashboard has something safe
    to show without reading the credential itself.

    Args:
        sanitized: output of sanitize_password()

    Returns dict to merge into the LAW record.
    """
    fields = {
        "password_present": sanitized["present"],
        "password_masked":  sanitized.get("masked"),
        "is_plaintext":     sanitized.get("is_plaintext", False),
    }
    if sanitized.get("_raw"):
        fields["password"] = sanitized["_raw"]
    return fields
