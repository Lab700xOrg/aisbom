"""CISA Known Exploited Vulnerabilities, for `aisbom comply --framework fda`.

CISA publishes the KEV catalogue: CVEs it has evidence are exploited in the
wild, each with the date it was added. The FDA pack's vulnerability table
marks each dependency CVE that appears there.

Contract
--------

**comply only, never `scan`.** The lookup runs when an FDA pack is built, so a
plain scan's network behaviour and its VEX files are unchanged. Skipped under
``--offline`` / ``AISBOM_OFFLINE`` and ``--no-kev-lookup`` /
``AISBOM_NO_KEV_LOOKUP``.

**What is sent.** One ``GET`` of the whole public catalogue. No CVE ID,
package name, version, path or file content leaves the machine: matching
happens locally. No request is made when there is no CVE to match.

**Cache.** The CVE-to-date map (not the full feed) is kept for 24 hours in the
CLI's config directory, so repeat pack builds make no request. A stale cache
is never used as a fallback: a failed refetch gives no answers.

**Enrichment, never the run.** Failures cost answers, never the pack: nothing
here raises into the CLI or changes an exit code.

PyInstaller constraint: ``requests`` only, already bundled.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

import requests

from .spdx_gen import _tool_version

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
SOURCE_NAME = "CISA KEV"
DISABLE_ENV_VAR = "AISBOM_NO_KEV_LOOKUP"
REQUEST_TIMEOUT_SECONDS = 15
CACHE_FILENAME = "kev_cache.json"
CACHE_TTL_SECONDS = 24 * 60 * 60
_CACHE_SCHEMA = 1
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# A sentinel so an explicit ``cache_dir=None`` (no cache) differs from "use the default".
_DEFAULT_CACHE_DIR = object()


@dataclass
class KevLookupResult:
    # CVE ID -> ISO date CISA added it, for the asked-about CVEs that are listed.
    added: Dict[str, str] = field(default_factory=dict)
    # Set whenever a catalogue was read, so "not listed" can name the version.
    catalog_version: Optional[str] = None
    error: Optional[str] = None


def disabled_by_env(environ: Mapping[str, str] = os.environ) -> bool:
    return bool(environ.get(DISABLE_ENV_VAR))


def normalise_cve(value: Any) -> Optional[str]:
    """``CVE-YYYY-NNNN`` in upper case, or None for anything that is not a CVE ID."""
    if not isinstance(value, str):
        return None
    candidate = value.strip().upper()
    return candidate if _CVE.match(candidate) else None


def _default_session() -> Any:
    """The HTTP client used when none is injected. A seam the test suite stubs."""
    return requests.Session()


def _default_cache_dir() -> Optional[Path]:
    # Imported lazily so tests that stub telemetry's config dir apply here too.
    from . import telemetry

    return telemetry.get_config_dir()


def _iso_date(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        return datetime.date.fromisoformat(value).isoformat()
    except ValueError:
        return None


def _parse_catalogue(payload: Any) -> Optional[tuple[Dict[str, str], Optional[str]]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        return None
    added: Dict[str, str] = {}
    for entry in payload["vulnerabilities"]:
        if not isinstance(entry, dict):
            continue
        cve = normalise_cve(entry.get("cveID"))
        date = _iso_date(entry.get("dateAdded"))
        if cve and date:
            added[cve] = date
    version = payload.get("catalogVersion")
    return added, version if isinstance(version, str) else None


def _read_cache(path: Optional[Path], now: float) -> Optional[tuple[Dict[str, str], Optional[str]]]:
    if path is None:
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("schema") != _CACHE_SCHEMA:
        return None
    try:
        fresh = now - float(data["fetched_at"]) < CACHE_TTL_SECONDS
    except (TypeError, KeyError, ValueError):
        return None
    added = data.get("added")
    if not fresh or not isinstance(added, dict):
        return None
    version = data.get("catalog_version")
    return ({str(k): str(v) for k, v in added.items()},
            version if isinstance(version, str) else None)


def _write_cache(path: Optional[Path], now: float, added: Dict[str, str],
                 version: Optional[str]) -> None:
    """Write-tmp-then-rename. Never raises."""
    if path is None:
        return
    tmp = path.with_suffix(".json.tmp")
    payload = {"schema": _CACHE_SCHEMA, "fetched_at": now,
               "catalog_version": version, "added": added}
    try:
        tmp.write_text(json.dumps(payload, separators=(",", ":")))
        tmp.replace(path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _fetch(session: Any) -> tuple[Dict[str, str], Optional[str]]:
    response = session.get(
        KEV_URL,
        timeout=REQUEST_TIMEOUT_SECONDS,
        headers={"User-Agent": f"aisbom-cli/{_tool_version()}"},
    )
    response.raise_for_status()
    parsed = _parse_catalogue(response.json())
    if parsed is None:
        raise ValueError("unexpected catalogue shape")
    return parsed


def _describe(exc: BaseException) -> str:
    if isinstance(exc, requests.RequestException):
        return f"{SOURCE_NAME} request failed ({type(exc).__name__})"
    return f"{SOURCE_NAME} lookup failed ({type(exc).__name__})"


def lookup_known_exploited(
    cve_ids: Iterable[Any],
    *,
    session: Any = None,
    cache_dir: Any = _DEFAULT_CACHE_DIR,
    now: Optional[float] = None,
) -> KevLookupResult:
    """KEV date-added for each listed CVE among ``cve_ids``. Never raises."""
    result = KevLookupResult()
    wanted = {c for c in (normalise_cve(i) for i in cve_ids) if c}
    if not wanted:
        return result
    try:
        now = time.time() if now is None else now
        directory = _default_cache_dir() if cache_dir is _DEFAULT_CACHE_DIR else cache_dir
        path = Path(directory) / CACHE_FILENAME if directory else None
        catalogue = _read_cache(path, now)
        if catalogue is None:
            catalogue = _fetch(session if session is not None else _default_session())
            _write_cache(path, now, *catalogue)
        added, result.catalog_version = catalogue
        result.added = {cve: added[cve] for cve in sorted(wanted) if cve in added}
    except Exception as exc:  # noqa: BLE001 - enrichment must never break a run
        result.added = {}
        result.catalog_version = None
        result.error = _describe(exc)
    return result
