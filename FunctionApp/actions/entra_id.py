"""
Microsoft Entra ID actions via Microsoft Graph API.
Graph auth uses Workload Identity Federation: UAMI → App Registration (secretless).
UAMI provides the identity, App Registration provides the Graph permissions.
Permissions are managed in the portal — no CLI script needed.
ROPC is optional and requires a separate public-client App Registration.
"""

import logging
import os
import time
import requests
from urllib.parse import quote

try:
    from azure.identity import ManagedIdentityCredential, ClientAssertionCredential
    from azure.core.exceptions import ClientAuthenticationError
except ImportError:
    ClientAuthenticationError = Exception
    ManagedIdentityCredential = None
    ClientAssertionCredential = None

logger = logging.getLogger("socradar.entra.graph")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LOGIN_URL   = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

# Properties the user lookup has to ask for by name. Graph answers
# GET /users/{id} with a fixed default set of eleven properties and
# accountEnabled is not one of them, so anything outside that set has to be
# selected or it never arrives and nobody is told.
LOOKUP_SELECT = "id,userPrincipalName,accountEnabled"


def _graph_request(method: str, url: str, headers: dict, json=None, timeout: int = 15, max_retries: int = 3):
    """
    Graph API request wrapper that handles 429 Retry-After throttling.
    Returns the final requests.Response after up to max_retries retries.
    Per-retry sleep is capped at 30s to avoid hanging the function host.
    Network errors bubble up as requests.RequestException (caller handles).
    """
    attempt = 0
    while True:
        if json is not None:
            resp = requests.request(method, url, headers=headers, json=json, timeout=timeout)
        else:
            resp = requests.request(method, url, headers=headers, timeout=timeout)
        # 429 means Graph rejected the request before doing anything with it, so
        # replaying it is safe whatever the method.
        #
        # 503/504 carry no such promise: the gateway may have carried the change
        # out and lost the reply. Replaying a directory mutation there had a
        # specific cost — the second attempt at an MFA-method delete answers 404
        # for work that already happened, and the caller writes "no action
        # taken" into the audit trail for an action nobody can undo. A read is
        # free to retry; a write is returned as-is so the caller reports "we do
        # not know" rather than something false.
        retryable = resp.status_code == 429 or (
            resp.status_code in (503, 504) and method.upper() in ("GET", "HEAD"))
        if not retryable or attempt >= max_retries:
            return resp
        retry_after_raw = resp.headers.get("Retry-After", "2")
        try:
            retry_after = int(retry_after_raw)
        except ValueError:
            retry_after = 2
        retry_after = max(1, min(retry_after, 30))
        logger.warning(
            "[ENTRA] HTTP %d on %s %s — sleeping %ds (attempt %d/%d)",
            resp.status_code, method, url.rsplit('/', 2)[-1], retry_after,
            attempt + 1, max_retries
        )
        time.sleep(retry_after)
        attempt += 1


class ConsentRevokedError(RuntimeError):
    """
    Token acquisition failed because the target tenant has not consented
    to the app, or consent was revoked. Distinct from transient errors.
    """
    def __init__(self, tenant_id: str, aadsts_code: str, message: str):
        self.tenant_id = tenant_id
        self.aadsts_code = aadsts_code
        super().__init__(message)


# AADSTS codes that specifically indicate missing or revoked consent.
# Reference: https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
# NOTE: AADSTS7000215 is NOT here — it means "Invalid client secret", which is a
# credential rotation issue, not a consent issue. Routing it through ConsentRevokedError
# would mislead operators into re-granting consent when they need to rotate the secret.
_CONSENT_AADSTS_CODES = {
    "AADSTS650052",   # App needs access to a service that your organization hasn't subscribed to
    "AADSTS650054",   # App removed by admin
    "AADSTS700016",   # App not found in directory (no service principal)
    "AADSTS700022",   # Multi-tenant app: tenant has not consented
    "AADSTS65001",    # User or admin has not consented to this app
    "AADSTS7000112",  # App disabled
    "AADSTS7000229",  # Application not authorized in this tenant
}


def _classify_token_error(err_description: str) -> str | None:
    """Return the first AADSTS code found in the description that indicates consent issue, else None."""
    if not err_description:
        return None
    for code in _CONSENT_AADSTS_CODES:
        if code in err_description:
            return code
    return None


# One store, not two. Held as a single (key, credential) pair because two
# separate globals cannot be published together: a thread that had written the
# credential but not yet its key left the pair inconsistent, and a second
# thread reading in that window took the cache-hit path and minted a token for
# the wrong tenant. A tuple assignment is one store, so every reader sees
# either the whole old pair or the whole new one.
#
# That mattered more than a stale token: the wrong token here means one
# company's leak run looking up, and acting on, another company's directory,
# while the audit row still names the first company's tenant.
_graph_credential: tuple | None = None


def _build_graph_credential(tenant_id: str, client_id: str):
    """
    Build a credential that uses UAMI → FIC → App Registration for Graph.
    UAMI provides secretless auth. App Registration provides Graph permissions.
    Permissions managed in portal (App Registration → API permissions).
    """
    uami_client_id = os.environ.get("AZURE_CLIENT_ID", "")
    if not uami_client_id or ManagedIdentityCredential is None:
        raise RuntimeError("AZURE_CLIENT_ID not set or azure-identity not installed")

    mi = ManagedIdentityCredential(client_id=uami_client_id)

    def _get_assertion():
        return mi.get_token("api://AzureADTokenExchange").token

    return ClientAssertionCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        func=_get_assertion,
    )


def get_graph_token(tenant_id: str, client_id: str) -> str:
    """
    Acquire Graph token via Workload Identity Federation (secretless).
    UAMI authenticates → gets exchange token → used as assertion for App Registration.
    App Registration's Graph permissions (portal-managed) apply.
    No client_secret needed.
    """
    global _graph_credential
    key = (tenant_id, client_id)
    # One read of the pair, one write of the pair. Two timers and the preview
    # endpoints all reach this function, so a credential must never be usable
    # apart from the key that says which tenant it belongs to.
    cached = _graph_credential
    if cached is None or cached[0] != key:
        credential = _build_graph_credential(tenant_id, client_id)
        _graph_credential = (key, credential)
    else:
        credential = cached[1]

    try:
        token = credential.get_token("https://graph.microsoft.com/.default")
        logger.info("[ENTRA] Graph token acquired via Workload Identity Federation")
        return token.token
    except ClientAuthenticationError as e:
        err_str = str(e)
        consent_code = _classify_token_error(err_str)
        if consent_code:
            raise ConsentRevokedError(tenant_id, consent_code, f"Consent issue ({consent_code}): {err_str}")
        raise RuntimeError(f"Graph token acquisition failed: {e}")
    except Exception as e:
        raise RuntimeError(f"Workload Identity Federation error: {e}")


def lookup_user(email: str, graph_headers: dict) -> tuple:
    """
    Look up a user in Entra ID by email (UPN).

    Returns a tuple (user_dict_or_none, http_status).
    Status is 0 if the request itself failed (network/timeout).
    Caller uses status to distinguish 404 (not found) from 403 (permission denied)
    without relying on module-level state (thread-safe for future MSSP concurrency).
    """
    # The address comes from a third-party feed. Dropped into the path unescaped,
    # a '#' truncates the request and a '?' turns the rest into query parameters,
    # so the lookup would silently ask about someone else.
    #
    # $select is not a nicety: Graph's default projection for GET /users/{id}
    # leaves accountEnabled OUT. Without asking for it the audit trail records
    # whether the account was live from a field that never arrived.
    url = (f"{GRAPH_BASE}/users/{quote(email, safe='@.')}"
           f"?$select={LOOKUP_SELECT}")
    try:
        resp = _graph_request("GET", url, graph_headers, timeout=15)
        if resp.status_code == 200:
            logger.debug("[ENTRA] lookup %s → found", email)
            return resp.json(), 200
        if resp.status_code == 404:
            logger.debug("[ENTRA] lookup %s → not_found", email)
            return None, 404
        logger.warning("[ENTRA] lookup %s → HTTP %d", email, resp.status_code)
        return None, resp.status_code
    except requests.RequestException as e:
        logger.error("[ENTRA] lookup %s → error: %s", email, e)
        return None, 0


def revoke_sessions(user_id: str, graph_headers: dict) -> bool:
    """Revoke all sign-in sessions for a user."""
    url = f"{GRAPH_BASE}/users/{user_id}/revokeSignInSessions"
    try:
        resp = _graph_request("POST", url, graph_headers, timeout=15)
        ok = resp.status_code in (200, 204)
        logger.info("[ENTRA] revokeSession %s → %s", user_id[:8], "ok" if ok else f"HTTP {resp.status_code}")
        return ok
    except requests.RequestException as e:
        logger.error("[ENTRA] revokeSession %s → error: %s", user_id[:8], e)
        return False


def add_to_group(user_id: str, group_id: str, graph_headers: dict) -> bool:
    """Add user to a security group."""
    url = f"{GRAPH_BASE}/groups/{group_id}/members/$ref"
    body = {"@odata.id": f"{GRAPH_BASE}/directoryObjects/{user_id}"}
    try:
        resp = _graph_request("POST", url, graph_headers, json=body, timeout=15)
        # 204 = added, 400 with "already exist[s]" = already member
        # Microsoft returns "already exist" (singular, no 's') in current Graph error messages.
        if resp.status_code == 204:
            logger.info("[ENTRA] addToGroup %s → ok", user_id[:8])
            return True
        if resp.status_code == 400 and "already exist" in resp.text.lower():
            logger.info("[ENTRA] addToGroup %s → already member", user_id[:8])
            return True
        logger.warning("[ENTRA] addToGroup %s → HTTP %d: %s", user_id[:8], resp.status_code, resp.text[:100])
        return False
    except requests.RequestException as e:
        logger.error("[ENTRA] addToGroup %s → error: %s", user_id[:8], e)
        return False


def remove_from_group(user_id: str, group_id: str, graph_headers: dict) -> bool:
    """Remove user from a security group."""
    url = f"{GRAPH_BASE}/groups/{group_id}/members/{user_id}/$ref"
    try:
        resp = _graph_request("DELETE", url, graph_headers, timeout=15)
        if resp.status_code == 204:
            logger.info("[ENTRA] removeFromGroup %s → ok", user_id[:8])
            return True
        if resp.status_code == 404:
            logger.info("[ENTRA] removeFromGroup %s → not a member", user_id[:8])
            return True
        logger.warning("[ENTRA] removeFromGroup %s → HTTP %d: %s", user_id[:8], resp.status_code, resp.text[:100])
        return False
    except requests.RequestException as e:
        logger.error("[ENTRA] removeFromGroup %s → error: %s", user_id[:8], e)
        return False


def disable_account(user_id: str, graph_headers: dict) -> bool:
    """Disable user account (accountEnabled=false)."""
    url = f"{GRAPH_BASE}/users/{user_id}"
    body = {"accountEnabled": False}
    try:
        resp = _graph_request("PATCH", url, graph_headers, json=body, timeout=15)
        ok = resp.status_code == 204
        logger.info("[ENTRA] disableAccount %s → %s", user_id[:8], "ok" if ok else f"HTTP {resp.status_code}")
        return ok
    except requests.RequestException as e:
        logger.error("[ENTRA] disableAccount %s → error: %s", user_id[:8], e)
        return False


def enable_account(user_id: str, graph_headers: dict) -> bool:
    """Re-enable a previously disabled user account."""
    url = f"{GRAPH_BASE}/users/{user_id}"
    body = {"accountEnabled": True}
    try:
        resp = _graph_request("PATCH", url, graph_headers, json=body, timeout=15)
        ok = resp.status_code == 204
        logger.info("[ENTRA] enableAccount %s → %s", user_id[:8], "ok" if ok else f"HTTP {resp.status_code}")
        return ok
    except requests.RequestException as e:
        logger.error("[ENTRA] enableAccount %s → error: %s", user_id[:8], e)
        return False


def force_password_change(user_id: str, graph_headers: dict) -> bool:
    """Force user to change password on next sign-in."""
    url = f"{GRAPH_BASE}/users/{user_id}"
    body = {
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "forceChangePasswordNextSignInWithMfa": False
        }
    }
    try:
        resp = _graph_request("PATCH", url, graph_headers, json=body, timeout=15)
        ok = resp.status_code == 204
        logger.info("[ENTRA] forcePasswordChange %s → %s", user_id[:8], "ok" if ok else f"HTTP {resp.status_code}")
        return ok
    except requests.RequestException as e:
        logger.error("[ENTRA] forcePasswordChange %s → error: %s", user_id[:8], e)
        return False


def confirm_compromised(user_id: str, graph_headers: dict) -> bool:
    """
    Confirm user as compromised in Identity Protection.
    Requires IdentityRiskyUser.ReadWrite.All and an Entra ID P2 licence
    (the riskyUsers API is P2, not P1 — the docs here used to overpromise).
    The call is on v1.0 now; it lived on beta long after Microsoft shipped
    it in v1.0, which was a compatibility bet with no upside.
    """
    url = f"{GRAPH_BASE}/identityProtection/riskyUsers/confirmCompromised"
    body = {"userIds": [user_id]}
    try:
        resp = _graph_request("POST", url, graph_headers, json=body, timeout=15)
        ok = resp.status_code == 204
        logger.info("[ENTRA] confirmRisky %s → %s", user_id[:8], "ok" if ok else f"HTTP {resp.status_code}")
        return ok
    except requests.RequestException as e:
        logger.error("[ENTRA] confirmRisky %s → error: %s", user_id[:8], e)
        return False


def validate_password_ropc(email: str, password: str, tenant_id: str, client_id: str) -> str:
    """
    Validate credential via ROPC (Resource Owner Password Credentials).

    WARNING: Microsoft discourages ROPC. Only use when explicitly enabled.
    Requires "Allow public client flows" in App Registration.

    Returns:
        "valid"       — credential is active and correct
        "invalid"     — password is wrong (user changed it)
        "mfa_blocked" — MFA required, can't validate via ROPC
        "error"       — unexpected error
    """
    url = LOGIN_URL.format(tenant=tenant_id)
    data = {
        "grant_type": "password",
        "client_id":  client_id,
        "username":   email,
        "password":   password,
        "scope":      "https://graph.microsoft.com/.default",
    }
    try:
        resp = requests.post(url, data=data, timeout=15)
        body = resp.json()

        if resp.status_code == 200 and "access_token" in body:
            logger.warning("[ENTRA:ROPC] %s → VALID CREDENTIAL (CRITICAL)", email)
            return "valid"

        error = body.get("error", "")
        error_desc = body.get("error_description", "")

        if "AADSTS50076" in error_desc or "AADSTS50079" in error_desc:
            logger.info("[ENTRA:ROPC] %s → mfa_blocked", email)
            return "mfa_blocked"

        if "AADSTS50126" in error_desc:
            logger.info("[ENTRA:ROPC] %s → invalid (wrong password)", email)
            return "invalid"

        logger.warning("[ENTRA:ROPC] %s → unexpected: %s", email, error_desc[:100])
        return "error"

    except requests.RequestException as e:
        logger.error("[ENTRA:ROPC] %s → request error: %s", email, e)
        return "error"
    finally:
        # Ensure password is not retained in any local traceback or closure
        del password


# =============================================================================
# Force MFA Re-registration
# =============================================================================

PASSWORD_METHOD_ID = "28c10230-6103-485e-b985-444c60001490"

METHOD_TYPE_TO_ENDPOINT = {
    "microsoft.graph.microsoftAuthenticatorAuthenticationMethod": "microsoftAuthenticatorMethods",
    "microsoft.graph.phoneAuthenticationMethod":                   "phoneMethods",
    "microsoft.graph.fido2AuthenticationMethod":                   "fido2Methods",
    "microsoft.graph.softwareOathAuthenticationMethod":            "softwareOathMethods",
    "microsoft.graph.windowsHelloForBusinessAuthenticationMethod": "windowsHelloForBusinessMethods",
    "microsoft.graph.emailAuthenticationMethod":                   "emailMethods",
    "microsoft.graph.temporaryAccessPassAuthenticationMethod":     "temporaryAccessPassMethods",
}


def force_mfa_reregistration(user_id: str, graph_headers: dict) -> dict:
    """
    Delete every non-password authentication method so the user must re-register
    MFA at next sign-in. Requires UserAuthenticationMethod.ReadWrite.All.

    Returns dict so caller can distinguish:
      - methods_deleted > 0      : at least one method was deleted
      - methods_skipped          : password method (always preserved)
      - permission_denied = True : 401/403 on list or delete (missing permission)
      - errors                   : list of per-method failure strings
    """
    result = {
        "methods_deleted": 0,
        "methods_skipped": 0,
        "errors": [],
        "permission_denied": False,
    }
    list_url = f"{GRAPH_BASE}/users/{user_id}/authentication/methods"
    try:
        resp = _graph_request("GET", list_url, graph_headers, timeout=20)
    except requests.RequestException as e:
        result["errors"].append(f"list methods request error: {e}")
        return result

    if resp.status_code in (401, 403):
        result["permission_denied"] = True
        result["errors"].append(f"list methods: HTTP {resp.status_code}")
        logger.warning(
            "[ENTRA] forceMfaRereg %s: permission denied (need UserAuthenticationMethod.ReadWrite.All)",
            user_id[:8]
        )
        return result
    if resp.status_code != 200:
        result["errors"].append(f"list methods: HTTP {resp.status_code} {resp.text[:200]}")
        return result

    for method in resp.json().get("value", []):
        method_id = method.get("id")
        odata_type = method.get("@odata.type", "").lstrip("#")
        if method_id == PASSWORD_METHOD_ID:
            result["methods_skipped"] += 1
            continue
        endpoint = METHOD_TYPE_TO_ENDPOINT.get(odata_type)
        if not endpoint:
            result["errors"].append(f"unknown method type: {odata_type}")
            continue
        del_url = f"{GRAPH_BASE}/users/{user_id}/authentication/{endpoint}/{method_id}"
        try:
            del_resp = _graph_request("DELETE", del_url, graph_headers, timeout=20)
        except requests.RequestException as e:
            result["errors"].append(f"delete {endpoint} request error: {e}")
            continue
        if del_resp.status_code == 204:
            result["methods_deleted"] += 1
        elif del_resp.status_code in (401, 403):
            result["permission_denied"] = True
            result["errors"].append(f"delete {endpoint}: HTTP {del_resp.status_code}")
            return result
        else:
            result["errors"].append(f"delete {endpoint}: HTTP {del_resp.status_code}")

    logger.info(
        "[ENTRA] forceMfaRereg %s → deleted=%d skipped=%d errors=%d",
        user_id[:8], result["methods_deleted"], result["methods_skipped"], len(result["errors"])
    )
    return result
