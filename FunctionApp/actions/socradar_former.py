"""
SOCRadar Former Employee list client.

Contract: DRP Former Employees API (openapi drp_former_employeeapi.yaml,
received 2026-07-16). Live-verified against platform.socradar.com: the add
endpoint validates its body (proves it is deployed, not the dark-web-monitoring
catch-all). Two implementations:

  - MockFormerListClient: stores the list in Azure Table Storage
    (table FormerListMock, PartitionKey = company_id, RowKey = email-safe key).
    Used for E2E without touching the platform. Reconcile semantics identical.

  - RealFormerListClient: calls the real endpoints. API quirks handled here:
      * HTTP is 200 even on logical errors — check body is_success/response_code.
      * Empty list comes back as data:null (not []).
      * delete with no matching records returns HTTP 404 with an HTML page
        (not JSON) — treated as "already absent" (desired state reached).
      * Every add/delete call requires an acting user "email" that must belong
        to the company on the platform (FORMER_ACTOR_EMAIL setting).

Selected via FORMER_CLIENT_MODE app setting: "mock" (default) or "real".
"""

import logging
import requests
from azure.data.tables import TableServiceClient, TableEntity
from azure.core.exceptions import ResourceNotFoundError, ResourceExistsError

logger = logging.getLogger("socradar.elite.former_client")

MOCK_TABLE = "FormerListMock"


def _email_row_key(email: str) -> str:
    # Hash, not escape. The old encoding replaced the four characters Table
    # Storage forbids with '_', which is lossy: 'a/b@x' and 'a_b@x' became the
    # same row, so one address could overwrite or delete another. A digest
    # cannot collide that way. The stored entity keeps the plain email in its
    # own column, so listing (which reads that column) never depended on the
    # key shape.
    import hashlib
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def _legacy_email_row_key(email: str) -> str:
    # The pre-hash scheme. It has to stay deletable: the manual store is NOT
    # transient — its rows survive reconciles by design, and an entry written
    # under this key before the hash change would otherwise be un-removable
    # (the delete would miss, its ResourceNotFoundError would be swallowed,
    # and the next sync would re-add the address from the still-visible row —
    # a suppression nobody could ever lift).
    return email.replace("/", "_").replace("\\", "_").replace("#", "_").replace("?", "_")


def _delete_email_row(table, company: str, email: str) -> bool:
    """Delete an email's row under whichever key scheme it was written with.
    Returns True if at least one row actually existed."""
    from azure.core.exceptions import ResourceNotFoundError as _NotFound
    deleted = False
    keys = {_email_row_key(email), _legacy_email_row_key(email)}
    for key in keys:
        try:
            table.delete_entity(partition_key=company, row_key=key)
            deleted = True
        except _NotFound:
            pass
    return deleted


class MockFormerListClient:
    """Table Storage backed stand-in for the future SOCRadar former API."""

    def __init__(self, storage_account_name: str, credential, company_id: str):
        url = f"https://{storage_account_name}.table.core.windows.net"
        service = TableServiceClient(endpoint=url, credential=credential)
        try:
            service.create_table(MOCK_TABLE)
        except ResourceExistsError:
            pass
        self._table = service.get_table_client(MOCK_TABLE)
        self._company = str(company_id)

    def get_list(self) -> set:
        emails = set()
        query = f"PartitionKey eq '{self._company}'"
        for entity in self._table.query_entities(query):
            emails.add(str(entity.get("email", "")).lower())
        emails.discard("")
        return emails

    def add(self, emails: list, source: str) -> int:
        added = 0
        for email in emails:
            entity = TableEntity()
            entity["PartitionKey"] = self._company
            entity["RowKey"] = _email_row_key(email)
            entity["email"] = email
            entity["source"] = source
            self._table.upsert_entity(entity)
            added += 1
        return added

    def remove(self, emails: list) -> int:
        removed = 0
        for email in emails:
            if _delete_email_row(self._table, self._company, email):
                removed += 1
        return removed


class RealFormerListClient:
    """Real SOCRadar DRP Former Employees API client.

    Endpoints (configuration-driven, defaults match the contract):
      GET  FORMER_LIST_PATH    /api/company/{company_id}/dark-web-monitoring/former-employees
      POST FORMER_ADD_PATH     /api/company/{company_id}/dark-web-monitoring/add-former-employee
                               body: {"formerEmployees": [emails], "comment": str, "email": actor}
      POST FORMER_REMOVE_PATH  /api/company/{company_id}/dark-web-monitoring/delete-former-employee
                               body: {"employeeEmails": [emails], "email": actor}
    """

    def __init__(self, base_url: str, api_key: str, company_id: str, actor_email: str,
                 list_path: str, add_path: str, remove_path: str, batch_size: int = 100,
                 timeout: int = 60):
        self._base = base_url.rstrip("/")
        # Explicit User-Agent: preprod sits behind Cloudflare which blocks the
        # default python-requests UA with a bot challenge (error 1010).
        self._headers = {"API-Key": api_key, "Content-Type": "application/json",
                         "User-Agent": "SOCRadar-EntraID-Elite/1.0"}
        self._company = str(company_id)
        self._actor = actor_email
        self._list_path = list_path
        self._add_path = add_path
        self._remove_path = remove_path
        self._batch = max(1, batch_size)
        # A 30s read timeout is too tight for a large former list behind
        # Cloudflare. Default 60s, configurable via FORMER_HTTP_TIMEOUT for
        # very large customers.
        self._timeout = max(5, timeout)

    def _url(self, path: str) -> str:
        return self._base + path.format(company_id=self._company)

    def _send(self, fn, before_retry=None):
        """Bounded retry: ONE retry with jittered backoff, only for transient
        classes — 429, 5xx, timeouts, connection drops (a Cloudflare 502 in
        front of the API is the motivating case). Permanent errors (4xx) return
        immediately; retries never loop unbounded.

        before_retry: optional hook fired once, just before the single retry.
        Returning False cancels the retry and makes _send return None —
        the add path uses it to readback-dedup a chunk whose first POST may
        have committed before the transient error (at-least-once window)."""
        import random
        import time as _time
        for attempt in (1, 2):
            try:
                resp = fn()
                if resp.status_code in (429,) or resp.status_code >= 500:
                    if attempt == 1:
                        wait = 1 + random.random() * 2
                        logger.warning("[FORMER] transient HTTP %d, retrying in %.1fs",
                                       resp.status_code, wait)
                        _time.sleep(wait)
                        if before_retry is not None and not before_retry():
                            return None
                        continue
                return resp
            except (requests.Timeout, requests.ConnectionError) as e:
                if attempt == 1:
                    wait = 1 + random.random() * 2
                    logger.warning("[FORMER] transient %s, retrying in %.1fs",
                                   type(e).__name__, wait)
                    _time.sleep(wait)
                    if before_retry is not None and not before_retry():
                        return None
                    continue
                raise
        return resp

    @staticmethod
    def _body_ok(resp) -> bool:
        """API returns HTTP 200 with is_success/response_code in the body."""
        try:
            payload = resp.json()
        except ValueError:
            return False
        return bool(payload.get("is_success")) and payload.get("response_code", 200) == 200

    def get_list(self) -> set:
        resp = self._send(lambda: requests.get(
            self._url(self._list_path), headers=self._headers, timeout=self._timeout))
        if resp.status_code != 200 or not self._body_ok(resp):
            raise RuntimeError(f"former list GET -> HTTP {resp.status_code}: {resp.text[:200]}")
        data = resp.json().get("data") or []  # empty list arrives as data:null
        emails = set()
        for entry in data:
            email = str((entry or {}).get("email", "")).strip().lower()
            if email:
                emails.add(email)
        return emails

    # The platform's add endpoint rejects a duplicate with is_success=false and
    # this message (observed live, 2026-08-01, company 330). The state we were
    # asked to reach — address on the list — already holds, so it counts as
    # done, exactly like a 404 on delete. Without this, every reconcile after
    # the first successful add logged an ERROR forever, because the list
    # endpoint reads back empty and the add is retried each run.
    _ALREADY_PRESENT = "already in database"

    def _post_batched(self, path: str, payload_fn, emails: list, missing_ok: bool = False,
                      already_ok: bool = False, dedup_on_retry: bool = False) -> int:
        done = 0
        for i in range(0, len(emails), self._batch):
            chunk_box = [emails[i:i + self._batch]]
            confirmed_pre = [0]

            def _before_retry():
                # The first POST may have committed before the transient error
                # (at-least-once window). If the add endpoint appends rather
                # than upserts, a blind re-POST would duplicate — re-read the
                # list, count already-present emails as done, retry the rest
                # only. False (nothing left) cancels the retry entirely.
                if not dedup_on_retry:
                    return True
                try:
                    existing = self.get_list()
                except RuntimeError:
                    return True  # readback unavailable — plain retry; the
                                 # caller's readback-confirm still audits
                present = [e for e in chunk_box[0] if e in existing]
                confirmed_pre[0] += len(present)
                chunk_box[0] = [e for e in chunk_box[0] if e not in existing]
                return bool(chunk_box[0])

            resp = self._send(
                lambda: requests.post(
                    self._url(path), json=payload_fn(chunk_box[0]),
                    headers=self._headers, timeout=self._timeout),
                before_retry=_before_retry)
            done += confirmed_pre[0]
            chunk = chunk_box[0]
            if resp is None:
                continue  # retry cancelled: every email already on the list
            if resp.status_code == 200 and self._body_ok(resp):
                done += len(chunk)
            elif missing_ok and resp.status_code == 404:
                # delete: HTML 404. Originally read as "no matching entry", but
                # observed live (2026-08-01, company 330): the delete route can
                # 404 while the record demonstrably exists — the add endpoint
                # still rejects it as a duplicate afterwards. A 404 therefore
                # proves nothing about the record. Counting it done keeps
                # reconciles from wedging, but the removal is UNVERIFIED and the
                # platform UI is the only place that can confirm it.
                logger.warning("[FORMER] POST %s: 404 — treated as removed, but this "
                               "platform can 404 while the record still exists; "
                               "verify removals in the platform UI", path)
                done += len(chunk)
            elif (already_ok and resp.status_code == 200
                  and self._ALREADY_PRESENT in resp.text):
                # add: the platform says the address is already a former
                # employee. Desired state (present) already holds; count as
                # done. This is also the only readable confirmation this API
                # gives that an earlier add landed — its list endpoint answers
                # data:null for every path.
                logger.info("[FORMER] POST %s: already on the list, treating as added", path)
                done += len(chunk)
            else:
                logger.error("[FORMER] POST %s failed: %d %s", path, resp.status_code, resp.text[:200])
        return done

    def add(self, emails: list, source: str) -> int:
        return self._post_batched(
            self._add_path,
            lambda chunk: {"formerEmployees": chunk, "comment": source, "email": self._actor},
            emails,
            already_ok=True,      # a duplicate rejection means the state holds
            dedup_on_retry=True,  # adversary 2026-07-25: server-side add
                                  # idempotency is unproven; never blind-re-POST
        )

    def remove(self, emails: list) -> int:
        return self._post_batched(
            self._remove_path,
            lambda chunk: {"employeeEmails": chunk, "email": self._actor},
            emails,
            missing_ok=True,
        )


def build_client(conf: dict, credential):
    """Factory: FORMER_CLIENT_MODE=mock (default) | real."""
    if conf["former_client_mode"] == "real":
        return RealFormerListClient(
            base_url=conf["socradar_base_url"],
            api_key=conf["socradar_api_key"],
            company_id=conf["socradar_company_id"],
            actor_email=conf["former_actor_email"],
            list_path=conf["former_list_path"],
            add_path=conf["former_add_path"],
            remove_path=conf["former_remove_path"],
            batch_size=conf["former_batch_size"],
            timeout=conf.get("former_http_timeout", 60),
        )
    return MockFormerListClient(
        storage_account_name=conf["storage_account_name"],
        credential=credential,
        company_id=conf["socradar_company_id"],
    )
