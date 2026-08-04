"""
Entra ID user enumeration for Former Employee sync.

Reads three user populations per tenant via Microsoft Graph:
  - active Members    (accountEnabled eq true,  userType eq 'Member')
  - disabled Members  (accountEnabled eq false, userType eq 'Member')
  - deleted users     (/directory/deletedItems/microsoft.graph.user, Member only)

All comparisons downstream are EMAIL-based (objectId is tenant-scoped and cannot
be compared across tenants). extract_emails() returns the union of mail,
smtp proxyAddresses and (as fallback) a plausible UPN, lowercased.
"""

import logging
import re
import time
import requests

logger = logging.getLogger("socradar.elite.entra_users")

# Graph throttles per tenant. Without this the whole tenant read fails, the
# snapshot is marked incomplete and the reconcile blocks — a throttle must not
# look like missing data.
_THROTTLE_RETRIES = 3
_THROTTLE_BACKOFF = 5

# Soft-deleted users get their objectId (32 hex chars, dashes removed) prepended
# to the userPrincipalName local part, e.g.
#   c5f5dcecc7234174b1d04bcab9f32e77elite-test-deleted@contoso.onmicrosoft.com
# That is not a routable address. Strip the prefix so leak matching sees the
# real UPN (or, when the whole local part IS the objectId, drop it entirely).
#
# The lookahead this once carried ((?=[^@])) required something after the hex,
# so the one case the comment singles out — a local part that is nothing but the
# objectId — matched nothing, kept its prefix and was published as an address.
# Nobody owns it, so reconcile could never retire it either.
_DELETED_UPN_PREFIX = re.compile(r"^[0-9a-f]{32}", re.IGNORECASE)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

USER_SELECT = "id,userPrincipalName,mail,proxyAddresses,userType,accountEnabled"


def _get_paged(url: str, graph_headers: dict, advanced: bool = False, timeout: int = 30) -> list:
    """GET a Graph collection, following @odata.nextLink. Returns list of objects.

    advanced=True adds ConsistencyLevel: eventual + $count=true (required by some
    filter combinations). Caller should retry with advanced=True on HTTP 400.
    """
    headers = dict(graph_headers)
    if advanced:
        headers["ConsistencyLevel"] = "eventual"
        if "$count=true" not in url:
            url += ("&" if "?" in url else "?") + "$count=true"

    items = []
    next_url = url
    while next_url:
        # Snapshot completeness: a poisoned @odata.nextLink must
        # never send our bearer token to a foreign host.
        if not next_url.startswith(GRAPH_BASE.split("/v1.0")[0] + "/"):
            raise RuntimeError(f"Graph nextLink left graph.microsoft.com: {next_url[:80]}")
        for attempt in range(_THROTTLE_RETRIES + 1):
            resp = requests.get(next_url, headers=headers, timeout=timeout)
            if resp.status_code not in (429, 503) or attempt == _THROTTLE_RETRIES:
                break
            delay = int(resp.headers.get("Retry-After") or _THROTTLE_BACKOFF * (attempt + 1))
            logger.warning("[ENTRA_USERS] HTTP %d, waiting %ds (attempt %d/%d)",
                           resp.status_code, delay, attempt + 1, _THROTTLE_RETRIES)
            time.sleep(min(delay, 60))
        if resp.status_code != 200:
            raise RuntimeError(f"Graph GET {next_url.split('?')[0]} -> HTTP {resp.status_code}: {resp.text[:200]}")
        payload = resp.json()
        items.extend(payload.get("value", []))
        next_url = payload.get("@odata.nextLink")
    return items


def _get_users_filtered(graph_headers: dict, filter_expr: str) -> list:
    """List /users with a filter; falls back to advanced query on HTTP 400."""
    url = f"{GRAPH_BASE}/users?$filter={filter_expr}&$select={USER_SELECT}&$top=999"
    try:
        return _get_paged(url, graph_headers, advanced=False)
    except RuntimeError as e:
        if "HTTP 400" in str(e):
            logger.info("[USERS] simple filter rejected, retrying with advanced query: %s", filter_expr)
            return _get_paged(url, graph_headers, advanced=True)
        raise


def get_active_members(graph_headers: dict) -> list:
    return _get_users_filtered(graph_headers, "accountEnabled eq true and userType eq 'Member'")


def get_disabled_members(graph_headers: dict) -> list:
    return _get_users_filtered(graph_headers, "accountEnabled eq false and userType eq 'Member'")


def get_deleted_members(graph_headers: dict) -> list:
    """Soft-deleted users (30-day window). userType is preserved on deleted
    objects; Guest records are filtered out client-side (deletedItems does not
    reliably support userType filters server-side)."""
    url = f"{GRAPH_BASE}/directory/deletedItems/microsoft.graph.user?$select={USER_SELECT}&$top=100"
    users = _get_paged(url, graph_headers, advanced=False)
    return [u for u in users if (u.get("userType") or "Member") == "Member"]


def extract_emails(user: dict) -> set:
    """Email identity set for one user: mail + smtp proxyAddresses (+ UPN fallback).

    UPN is included only when it looks like a routable address (contains '@' and
    no '#EXT#' guest mangling). All values lowercased.
    """
    emails = set()

    mail = (user.get("mail") or "").strip().lower()
    if mail and "@" in mail:
        emails.add(mail)

    for proxy in user.get("proxyAddresses") or []:
        p = str(proxy).strip()
        if p.lower().startswith("smtp:"):
            addr = p[5:].strip().lower()
            if addr and "@" in addr:
                emails.add(addr)

    upn = (user.get("userPrincipalName") or "").strip().lower()
    if upn and "@" in upn and "#ext#" not in upn:
        local, _, domain = upn.partition("@")
        stripped = _DELETED_UPN_PREFIX.sub("", local)
        # Only treat UPN as an email when it is clean (no mangled objectId
        # prefix) OR the prefix was cleanly removable. If after stripping the
        # local part is empty, the UPN carried no real address — skip it.
        if stripped:
            emails.add(f"{stripped}@{domain}")

    return emails


def emails_of(users: list) -> set:
    """Flatten a user list into a lowercase email set."""
    out = set()
    for u in users:
        out |= extract_emails(u)
    return out
