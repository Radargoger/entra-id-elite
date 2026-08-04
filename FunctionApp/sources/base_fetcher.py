"""
Base fetcher for SOCRadar paginated API data sources.
Handles pagination, checkpoint management, deadline control, rate limiting.
Subclasses implement _map_record() for source-specific record mapping.
"""

import os
import time
import requests
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from utils.logger import get_logger
from utils.checkpoint import get_start_date

MAX_PAGES_PER_RUN = int(os.environ.get("MAX_PAGES_PER_RUN", "50"))
PAGE_SIZE = 100


class BaseFetcher(ABC):
    """Base class for paginated SOCRadar API fetchers.

    Provides the full pagination loop, checkpoint bookkeeping, deadline control
    and rate limiting.  Subclasses only override ``_map_record`` (required) and
    optionally ``_validate_response`` for custom HTTP status handling.
    """

    def __init__(self, source_name: str, endpoint_template: str,
                 page_size: int = PAGE_SIZE):
        self.source_name = source_name
        self.endpoint_template = endpoint_template
        self.page_size = page_size
        self.logger = get_logger(source_name)
        self._tag = source_name.upper()

    # ------------------------------------------------------------------
    # Subclass hooks
    # ------------------------------------------------------------------

    @abstractmethod
    def _map_record(self, rec: dict, conf: dict) -> dict | None:
        """Map a raw API record to a normalised entry dict.

        Return ``None`` to skip the record (e.g. employee filter).
        """
        ...

    def _validate_response(self, resp, page: int) -> bool:
        """Check HTTP response status.  Return True if valid, False to stop.

        Every non-200 used to read the same way in the log, so a throttle, an
        expired key and a server fault were indistinguishable to whoever had to
        act on them. Stopping is right in all three cases — the window is held
        and read again — but the reason has to survive into the log, because the
        three need different people to fix them.
        """
        if resp.status_code == 200:
            return True
        code = resp.status_code
        if code == 429:
            self.logger.error(
                "Throttled by the feed on page %d (HTTP 429, Retry-After=%s). "
                "Stopping here; the window is held and read again next run.",
                page, resp.headers.get("Retry-After", "unset")
                if hasattr(resp, "headers") else "unset",
            )
        elif code in (401, 403):
            self.logger.error(
                "The feed rejected our credentials on page %d (HTTP %d). "
                "This does not clear by itself — check the API key and the "
                "company's entitlement for this source.", page, code,
            )
        elif code >= 500:
            self.logger.error(
                "The feed failed on page %d (HTTP %d) — server side, transient. "
                "The window is held and read again next run.", page, code,
            )
        else:
            self.logger.error("API error %d on page %d: %s",
                              code, page, resp.text[:200])
        return False

    # ------------------------------------------------------------------
    # Main fetch loop
    # ------------------------------------------------------------------

    def fetch(self, conf: dict, checkpoint: dict, deadline: float = None,
              max_records: int = None) -> list:
        """Fetch records with pagination, respecting deadline and page cap."""
        company_id = conf["socradar_company_id"]
        api_key = conf["socradar_api_key"]
        initial_lookback = conf.get("initial_lookback_minutes", 600)
        initial_start_date = conf.get("initial_start_date", "")

        base = conf.get("socradar_base_url", "https://platform.socradar.com")
        url = base + self.endpoint_template.format(company_id=company_id)
        headers = {
            "API-Key": api_key,
            "Content-Type": "application/json",
            "User-Agent": "SOCRadar-EntraID/1.0",
        }

        start_date = get_start_date(checkpoint, initial_lookback, initial_start_date)
        resume_page = checkpoint.get("last_page", 0)
        self.logger.info(
            f"[{self._tag}] Starting fetch. start_date=%s, page=%d",
            start_date, resume_page + 1,
        )

        all_records: list[dict] = []
        page = resume_page + 1 if resume_page else 1
        # Init total_pages so the first loop iteration always runs (real value
        # comes from the first API response). Using 1 here breaks resume: if
        # resume_page=100 then page=101 and `page <= total_pages` is False, the
        # loop never executes, and `finished_all` becomes True erroneously --
        # checkpoint advances to today and the remaining backlog is lost.
        total_pages = page
        total_data_count = None
        count_known = False
        empty_before_end = False
        pages_this_run = 0

        max_pages = int(conf.get("max_pages_per_run") or MAX_PAGES_PER_RUN)
        # Pulling more than the caller can look up wastes the work: the
        # checkpoint is held back and the next run re-reads the same pages,
        # so the feed never advances.
        stopped_short = False
        while page <= total_pages and pages_this_run < max_pages:
            if max_records is not None and len(all_records) >= max_records:
                stopped_short = True
                self.logger.info(
                    f"[{self._tag}] Fetched %d records (this run's capacity)"
                    " -- resuming at page %d next run.",
                    len(all_records), page,
                )
                break
            if deadline is not None and time.time() >= deadline:
                stopped_short = True
                self.logger.info(
                    f"[{self._tag}] Fetch window closed"
                    " -- resuming at page %d next run.", page,
                )
                break

            params = {
                "page": page,
                "limit": self.page_size,
                "startDate": start_date,
            }

            try:
                resp = requests.get(url, headers=headers, params=params,
                                    timeout=30)
            except requests.RequestException as e:
                self.logger.error(f"Request failed on page {page}: {e}")
                break

            if not self._validate_response(resp, page):
                break

            data = resp.json()
            if not data.get("is_success"):
                self.logger.error(
                    f"API returned is_success=false: "
                    f"{data.get('message', 'unknown')}"
                )
                break

            payload = data.get("data", {})
            records_raw = payload.get("data", [])

            if total_data_count is None:
                total_data_count = payload.get("total_data_count")
                count_known = total_data_count is not None
                if count_known:
                    total_pages = max(1, -(-total_data_count // self.page_size))  # ceiling division
                else:
                    # The feed did not say how much there is. Defaulting that to
                    # zero made total_pages 1, so a full first page ended the run
                    # as "finished", the window jumped to today and every page
                    # behind it was dropped and never re-read. With no count to
                    # trust, keep asking while pages come back full and let a
                    # short page mark the end.
                    total_pages = page
                self.logger.info(
                    "Total records=%s, pages=%s",
                    total_data_count if count_known else "unreported",
                    total_pages if count_known else "until a short page",
                )

            employees_this_page = 0
            skipped_this_page = 0

            for rec in records_raw:
                entry = self._map_record(rec, conf)
                if entry is None:
                    skipped_this_page += 1
                    continue
                all_records.append(entry)
                employees_this_page += 1

            self.logger.fetch_page(
                page=page,
                total_pages=total_pages,
                records=len(records_raw),
                employees=employees_this_page,
                skipped=skipped_this_page,
            )

            if not records_raw:
                # An empty page means the window is exhausted, not that the
                # fetch broke.  Advance so the date moves on; otherwise every
                # later run re-queries the same empty window forever.
                #
                # Unless it arrives early: when the feed reported a count and we
                # are not near it yet, it promised more and sent nothing.
                # Advancing there marked that page consumed for good.
                if count_known and page < total_pages:
                    empty_before_end = True
                    self.logger.error(
                        "Page %d of %d came back empty though the feed reported "
                        "%s records — holding this page rather than skipping it",
                        page, total_pages, total_data_count,
                    )
                    break
                page += 1
                break

            if not count_known and len(records_raw) >= self.page_size:
                # A full page with no count to check it against: assume there is
                # one more and re-check on the next pass.
                total_pages = page + 1

            pages_this_run += 1
            page += 1
            time.sleep(1)  # rate limit: 1 req/sec

        self.logger.fetch_done(total=total_data_count or 0,
                               employees=len(all_records))

        # Checkpoint: if we finished all pages, reset page to 0 and advance
        # date.  If we hit the per-run limit, save current page so next run
        # resumes here.
        finished_all = page > total_pages and not stopped_short
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        checkpoint_update = {
            "last_start_date": today_str if finished_all else start_date,
            "last_page": 0 if finished_all else page - 1,
        }

        # Stopping before the last page without having hit the per-run page
        # limit means a request failed.  Without this the caller reports a
        # clean run with zero findings for a feed it never actually reached.
        # A run that stopped on its page cap, its clock or its capacity is not
        # a failure -- it resumes.  Anything else means a request broke, and
        # that must not be reported as a clean empty run.
        fetch_failed = (not finished_all and not stopped_short
                        and pages_this_run < max_pages) or empty_before_end

        if not finished_all and not fetch_failed:
            self.logger.info(
                f"[{self._tag}] Paused at page %d/%d (limit %d/run)."
                " Will resume next run.",
                page - 1, total_pages, max_pages,
            )

        if fetch_failed:
            # The marker carries the failure, and the checkpoint rides with it.
            # Attaching the flag to the last real record instead meant it was
            # only ever read on runs that returned nothing at all: a request that
            # broke after the first page reported errors=0 and read as a clean
            # run over a feed it had stopped talking to.
            all_records.append({
                "_checkpoint_update": checkpoint_update,
                "_empty_marker": True,
                "_fetch_failed": True,
            })
        elif all_records:
            all_records[-1]["_checkpoint_update"] = checkpoint_update
        else:
            all_records.append({
                "_checkpoint_update": checkpoint_update,
                "_empty_marker": True,
                "_fetch_failed": False,
            })

        return all_records
