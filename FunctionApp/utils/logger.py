"""
Structured logging utilities with source prefix and password filtering.
All log output goes through standard Python logging (captured by App Insights).
Passwords NEVER appear in any log output.
"""

import logging
import re

_PASSWORD_PATTERN = re.compile(
    r'(password|passwd|pwd|credential|secret|token)\s*[=:]\s*\S+',
    re.IGNORECASE
)
_REDACT = r'\1=***REDACTED***'


def _redact(msg: str) -> str:
    """Strip any accidental password-like values from a log string."""
    return _PASSWORD_PATTERN.sub(_REDACT, str(msg))


class SourceLogger:
    """Prefixed logger for a specific data source."""

    def __init__(self, source: str):
        self._src = source.upper()
        self._log = logging.getLogger(f"socradar.entra.{source.lower()}")

    def _fmt(self, msg: str) -> str:
        return f"[{self._src}] {_redact(msg)}"

    def info(self, msg: str, *args):
        self._log.info(self._fmt(msg), *args)

    def warning(self, msg: str, *args):
        self._log.warning(self._fmt(msg), *args)

    def error(self, msg: str, *args):
        self._log.error(self._fmt(msg), *args)

    def debug(self, msg: str, *args):
        self._log.debug(self._fmt(msg), *args)

    def fetch_start(self, start_epoch: int, page: int = 1):
        self.info(f"Starting fetch. start_epoch={start_epoch}, page={page}")

    def fetch_page(self, page: int, total_pages: int, records: int, employees: int, skipped: int = 0):
        self.info(
            f"Page {page}/{total_pages}: {records} records, "
            f"{employees} employees, {skipped} skipped"
        )

    def fetch_done(self, total: int, employees: int):
        self.info(f"Fetch complete. total={total}, employees={employees}")

    def action(self, email: str, action: str, result: str):
        self.info(f"Action on {email}: {action} → {result}")

    def lookup(self, email: str, status: str):
        self.info(f"Lookup {email}: {status}")

    def checkpoint_saved(self, **kwargs):
        kv = ", ".join(f"{k}={v}" for k, v in kwargs.items())
        self.info(f"Checkpoint saved. {kv}")


def get_logger(source: str) -> SourceLogger:
    return SourceLogger(source)


def audit_summary(source: str, total: int, employees: int,
                  found: int, not_found: int, actions: int,
                  errors: int, duration_sec: float,
                  domain_filtered: int = 0):
    log = logging.getLogger("socradar.entra.audit")
    log.info(
        "[AUDIT] source=%s total=%d employees=%d found=%d not_found=%d "
        "domain_filtered=%d actions=%d errors=%d duration=%.1fs",
        source, total, employees, found, not_found, domain_filtered,
        actions, errors, duration_sec
    )
