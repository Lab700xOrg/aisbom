"""End-of-support dates from endoflife.date, for `aisbom comply --framework fda`.

FDA's premarket cybersecurity guidance asks for the support status of each
component. For the packages endoflife.date tracks (numpy, Django, Python …) it
publishes an end-of-life date per release cycle. This module looks up the
cycle each exact pin belongs to and reports that date.

Contract
--------

**comply only, never `scan`.** The lookup runs when an FDA pack is built, so a
plain scan's network behaviour and SBOM are unchanged. Skipped under
``--offline`` / ``AISBOM_OFFLINE`` and ``--no-eol-lookup``.

**What is sent.** One ``GET /api/v1/products/<package name>`` per distinct
package. Package names only: no versions, no paths, no file contents.

**Nothing is guessed.** A product is used only when endoflife.date lists the
dependency's own PyPI purl (``pkg:pypi/<name>``) among its identifiers, so a
same-named product that is not the PyPI package cannot lend its dates. A pin
outside every listed cycle, a cycle with no announced date, an untracked
package and every failure all give no answer, and the component stays TODO.

**Enrichment, never the run.** Failures cost answers, never the pack: nothing
here raises into the CLI or changes an exit code.

PyInstaller constraint: ``requests`` and ``packaging`` only, both bundled.
"""

from __future__ import annotations

import datetime
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import quote

import requests
from packaging.utils import canonicalize_name

from .spdx_gen import _tool_version

EOL_API = "https://endoflife.date/api/v1/products"
SOURCE_NAME = "endoflife.date"
DISABLE_ENV_VAR = "AISBOM_NO_EOL_LOOKUP"
REQUEST_TIMEOUT_SECONDS = 5
LOOKUP_BUDGET_SECONDS = 15
_FETCH_WORKERS = 8


class EolUnavailable(Exception):
    """A lookup that cannot produce an answer."""


@dataclass(frozen=True)
class EolAnswer:
    date: str        # ISO date the cycle's support ends
    product: str
    cycle: str

    @property
    def source(self) -> str:
        return f"{SOURCE_NAME} {self.product} {self.cycle}"


@dataclass
class EolLookupResult:
    # Keyed on the (name, version) exactly as given, so callers join on their own values.
    answers: Dict[Tuple[str, str], EolAnswer] = field(default_factory=dict)
    queried: int = 0
    error: Optional[str] = None


def disabled_by_env(environ: Mapping[str, str] = os.environ) -> bool:
    return bool(environ.get(DISABLE_ENV_VAR))


def _default_session() -> Any:
    """The HTTP client used when none is injected. A seam the test suite stubs."""
    return requests.Session()


def _iso_date(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        return datetime.date.fromisoformat(value).isoformat()
    except ValueError:
        return None


def _cycles(payload: Any, canonical: str) -> Optional[List[Tuple[str, Optional[str]]]]:
    """[(cycle name, eol date or None)] for a product that is this PyPI package."""
    result = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(result, dict):
        return None
    identifiers = result.get("identifiers")
    purl = f"pkg:pypi/{canonical}"
    if not isinstance(identifiers, list) or not any(
        isinstance(i, dict) and i.get("type") == "purl"
        and isinstance(i.get("id"), str) and i["id"].lower() == purl
        for i in identifiers
    ):
        return None
    releases = result.get("releases")
    if not isinstance(releases, list):
        return None
    return [
        (r["name"], _iso_date(r.get("eolFrom")))
        for r in releases
        if isinstance(r, dict) and isinstance(r.get("name"), str) and r["name"]
    ]


def _cycle_for(version: str, cycles: List[Tuple[str, Optional[str]]]) -> Optional[Tuple[str, Optional[str]]]:
    """The longest cycle name that equals the version or prefixes it at a dot."""
    matches = [c for c in cycles if version == c[0] or version.startswith(c[0] + ".")]
    return max(matches, key=lambda c: len(c[0])) if matches else None


class _Client:
    def __init__(self, session: Any, budget_seconds: float):
        self.session = session
        self.deadline = time.monotonic() + budget_seconds
        self.headers = {"User-Agent": f"aisbom-cli/{_tool_version()}"}

    def product(self, slug: str) -> Optional[Any]:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise EolUnavailable("endoflife.date lookup exceeded its time budget")
        response = self.session.get(
            f"{EOL_API}/{quote(slug, safe='')}",
            timeout=min(REQUEST_TIMEOUT_SECONDS, remaining),
            headers=self.headers,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        try:
            return response.json()
        except ValueError:
            return None


def _describe(exc: BaseException) -> str:
    if isinstance(exc, EolUnavailable):
        return str(exc)
    if isinstance(exc, requests.RequestException):
        return f"endoflife.date request failed ({type(exc).__name__})"
    return f"endoflife.date lookup failed ({type(exc).__name__})"


def lookup_end_of_support(
    pins: Iterable[Tuple[str, str]],
    *,
    session: Any = None,
    budget_seconds: float = LOOKUP_BUDGET_SECONDS,
) -> EolLookupResult:
    """End-of-support dates for exact ``(name, version)`` pins. Never raises."""
    result = EolLookupResult()
    pins = list(dict.fromkeys(pins))
    by_product: Dict[str, List[Tuple[str, str]]] = {}
    for name, version in pins:
        by_product.setdefault(canonicalize_name(name), []).append((name, version))
    result.queried = len(by_product)
    if not by_product:
        return result

    failures: List[str] = []
    try:
        client = _Client(session if session is not None else _default_session(),
                         budget_seconds)
        with ThreadPoolExecutor(max_workers=min(_FETCH_WORKERS, len(by_product))) as pool:
            futures = {slug: pool.submit(client.product, slug) for slug in by_product}
        for slug, future in futures.items():
            try:
                payload = future.result()
            except Exception as exc:  # noqa: BLE001 - one package, not the run
                failures.append(_describe(exc))
                continue
            cycles = _cycles(payload, slug)
            if not cycles:
                continue
            for name, version in by_product[slug]:
                match = _cycle_for(version, cycles)
                if match and match[1]:
                    result.answers[(name, version)] = EolAnswer(match[1], slug, match[0])
    except Exception as exc:  # noqa: BLE001 - enrichment must never break a run
        failures.append(_describe(exc))

    if failures:
        result.error = (
            f"endoflife.date lookup failed for {len(failures)} of "
            f"{result.queried} package(s) ({failures[0]})"
        )
    return result
