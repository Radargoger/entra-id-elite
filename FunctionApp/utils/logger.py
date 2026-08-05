"""
Structured logging utilities with source prefix and secret filtering.
All log output goes through standard Python logging (captured by App Insights).
Lines that pass through SourceLogger are scrubbed of password/API-key-shaped
values. Modules that log through a plain logging.getLogger are NOT covered --
they must never log config rows, headers or raw response bodies.
"""

import logging
import re

# The API key is the one credential this app holds for the platform, so it
# belongs in this list beside the passwords. Two spellings had to be covered:
# `apiKey=...` and the JSON form `{"apiKey": "..."}`. The optional quote before
# the separator is what catches the second one -- a pattern anchored straight
# to [=:] walks past the quote and leaves the value in the clear.
# The value is either one quoted string or one whitespace-delimited run: a
# character-class that stopped at , ; } redacted `password=ab,cd` only up to
# the comma and let the tail through. An Authorization value may carry a
# `Bearer ` prefix before the part that must go.
_SECRET_PATTERN = re.compile(
    r'(password|passwd|pwd|credential|secret|token|api[-_]?key|authorization)'
    r'["\']?\s*[=:]\s*(?:[Bb]earer\s+)?(?:"[^"]*"|\'[^\']*\'|\S+)',
    re.IGNORECASE
)

# Naming the field rather than shouting REDACTED keeps the line readable and
# does not advertise to whoever reads the log that a live secret was here.
_PLACEHOLDERS = {
    'password': 'your_password',
    'passwd': 'your_password',
    'pwd': 'your_password',
    'credential': 'your_credential',
    'secret': 'your_secret',
    'token': 'your_token',
    'authorization': 'your_token',
}


def _placeholder(match: 're.Match') -> str:
    """Swap a matched secret for a neutral, field-named placeholder."""
    name = match.group(1)
    return f"{name}={_PLACEHOLDERS.get(name.lower(), 'your_key')}"


def _redact(msg: str) -> str:
    """Strip any accidental secret-like values from a log string."""
    return _SECRET_PATTERN.sub(_placeholder, str(msg))


class SourceLogger:
    """Prefixed logger for a specific data source."""

    def __init__(self, source: str):
        self._src = source.upper()
        self._log = logging.getLogger(f"socradar.entra.{source.lower()}")

    def _fmt(self, msg: str, args: tuple) -> str:
        """Render first, redact the whole line. Redacting only the format
        string let a secret through whenever it arrived as an argument —
        `log.error("response: %s", body)` printed the body untouched, which is
        exactly how an external API's echoed credential would reach App
        Insights. A failed render falls back to the unformatted pieces rather
        than losing the log line."""
        if args:
            try:
                msg = str(msg) % args
            except (TypeError, ValueError):
                msg = f"{msg} {args!r}"
        return f"[{self._src}] {_redact(msg)}"

    def info(self, msg: str, *args):
        self._log.info(self._fmt(msg, args))

    def warning(self, msg: str, *args):
        self._log.warning(self._fmt(msg, args))

    def error(self, msg: str, *args):
        self._log.error(self._fmt(msg, args))

    def debug(self, msg: str, *args):
        self._log.debug(self._fmt(msg, args))

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
                  domain_filtered: int = 0, no_address: int = 0,
                  lookup_disabled: int = 0, no_token: int = 0,
                  lookup_failed: int = 0):
    log = logging.getLogger("socradar.entra.audit")
    log.info(
        "[AUDIT] source=%s total=%d employees=%d found=%d not_found=%d "
        "no_address=%d lookup_disabled=%d no_token=%d lookup_failed=%d domain_filtered=%d "
        "actions=%d errors=%d duration=%.1fs",
        source, total, employees, found, not_found, no_address,
        lookup_disabled, no_token, lookup_failed, domain_filtered, actions, errors, duration_sec
    )
