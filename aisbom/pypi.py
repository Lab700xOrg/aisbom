"""PyPI license resolution for pinned requirements.txt dependencies (#129).

Library components parsed from ``requirements.txt`` carried a name and a
version and nothing else, so every SBOM lost most of the completeness grade's
Licenses dimension (#114) for information PyPI publishes. This module asks
PyPI's JSON API what each exact pin declares and records it on the dependency,
where the CycloneDX and SPDX 2.3 generators pick it up.

Contract
--------

**Enrichment, never the scan.** A PyPI outage, a rate limit, an unknown
package, a malformed body or an exhausted time budget costs that dependency its
license and nothing else. Nothing here raises into the CLI or changes an exit
code — the same asymmetry as the HF model-card fetch (#111) and the OSV lookup
(#128). Unlike OSV, a *partial* answer is fine: a license resolved for torch
says nothing about transformers, whereas a partial CVE list reads as complete.

**A declaration, never a verdict.** The result is written to the dependency's
``license`` and never to ``legal_status``. That field drives a compliance
judgement (the CLI's LEGAL RISK label, the platform's ``license_issue_count``),
and deriving it from registry metadata nobody reviewed would be a silent
verdict change — the same reason Hugging Face card licenses stay out of it
(#111).

**Only exact pins are looked up.** ``torch>=2.0`` does not say which release
is installed, and licenses do change between releases.

**Nothing is guessed.** Sources are tried from most to least precise: the PEP
639 ``license_expression``, then a valid SPDX id or expression in ``license``,
then a short list of unambiguous free-text spellings, then a classifier that
names exactly one license, then any other short declaration kept verbatim as a
license *name*. A license text pasted into the field (numpy ships 46KB of it)
and a classifier that does not say which license it means (``BSD License``)
resolve to nothing.

**Cached on disk.** A CI job scanning the same ``requirements.txt`` on every
push must not hit PyPI every time. Answers live in
``~/.aisbom/pypi_license_cache.json``: a resolved license for
:data:`RESOLVED_TTL_SECONDS` (a published release's metadata does not change),
an unknown package or undeclared license for :data:`UNRESOLVED_TTL_SECONDS`.
Failures are never cached.

PyInstaller constraint: ``requests``, ``packaging`` and ``cyclonedx`` only, all
already bundled.
"""

from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import quote

import requests
from cyclonedx import spdx
from packaging.utils import canonicalize_name

from .spdx_gen import _tool_version

PYPI_API = "https://pypi.org/pypi"
LICENSE_SOURCE = "pypi"
# Names where a dependency's license came from, so a consumer can tell a
# registry declaration apart from one AIsbom read out of the artifact itself.
LICENSE_SOURCE_PROPERTY = "aisbom:license:source"

CACHE_FILENAME = "pypi_license_cache.json"
RESOLVED_TTL_SECONDS = 30 * 24 * 60 * 60
UNRESOLVED_TTL_SECONDS = 24 * 60 * 60
_CACHE_SCHEMA = 1

REQUEST_TIMEOUT_SECONDS = 5
LOOKUP_BUDGET_SECONDS = 15
_FETCH_WORKERS = 8
_ATTEMPTS = 3
_BACKOFF_SECONDS = 0.5
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

# Free text longer than this is a license *text*, not a declaration of one.
_MAX_NAME_LENGTH = 64
_MAX_EXPRESSION_LENGTH = 512

_DEFAULT_CACHE_DIR = object()


class PyPIUnavailable(Exception):
    """A lookup that cannot produce an answer for this dependency."""


@dataclass(frozen=True)
class ResolvedLicense:
    value: str
    # True when ``value`` is a valid SPDX id or expression. SPDX 2.3 can only
    # carry those in ``licenseDeclared``; anything else stays a CycloneDX name.
    is_spdx: bool


@dataclass
class LicenseLookupResult:
    queried: int = 0
    resolved: int = 0
    failed: int = 0
    skipped_unpinned: int = 0
    error: Optional[str] = None


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------

# Free-text spellings that name exactly one SPDX license. Keys are compared
# after `_spelling_key` (casefolded, commas dropped, whitespace collapsed).
# Deliberately absent: bare "BSD", "GPL", "Apache" — each leaves the version or
# variant unsaid, so they are kept as names rather than promoted to an id.
_SPELLINGS: Dict[str, str] = {
    "apache 2.0 license": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license version 2.0": "Apache-2.0",
    "apache license v2.0": "Apache-2.0",
    "apache software license 2.0": "Apache-2.0",
    "apache-2.0 license": "Apache-2.0",
    "mit license": "MIT",
    "the mit license": "MIT",
    "bsd 3-clause license": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-3-clause license": "BSD-3-Clause",
    "3-clause bsd license": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "bsd 2-clause license": "BSD-2-Clause",
    "bsd-2-clause license": "BSD-2-Clause",
    "2-clause bsd license": "BSD-2-Clause",
    "simplified bsd license": "BSD-2-Clause",
    "isc license": "ISC",
    "mozilla public license 2.0": "MPL-2.0",
    "the unlicense": "Unlicense",
}

# Trove classifiers that name exactly one SPDX license. `BSD License`,
# `Apache Software License` and the unversioned GPL/LGPL classifiers are absent
# on purpose: they do not say which license they mean.
_CLASSIFIERS: Dict[str, str] = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: MIT No Attribution License (MIT-0)": "MIT-0",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    "License :: OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0",
    "License :: OSI Approved :: Boost Software License 1.0 (BSL-1.0)": "BSL-1.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: OSI Approved :: zlib/libpng License": "Zlib",
    "License :: OSI Approved :: Universal Permissive License (UPL)": "UPL-1.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication": "CC0-1.0",
}

# Parent nodes of the trove hierarchy. Packages often list one beside the leaf
# (`License :: OSI Approved` and `License :: OSI Approved :: MIT License`); it
# names no license, so it is not a second declaration.
_CATEGORY_CLASSIFIERS = frozenset({
    "License :: OSI Approved",
    "License :: DFSG approved",
})

_PLACEHOLDERS = frozenset({
    "unknown", "none", "null", "n/a", "na", "other", "license", "licence",
})
_LICENSE_FILENAME = re.compile(r"^licen[cs]e(\.[a-z0-9]+)?$", re.IGNORECASE)


def _single_line(value: Any, limit: int) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or "\n" in text or len(text) > limit:
        return None
    return text


def _as_spdx(value: Any, limit: int) -> Optional[str]:
    """``value`` as a canonical SPDX id or a valid expression, else None."""
    text = _single_line(value, limit)
    if text is None:
        return None
    canonical = spdx.fixup_id(text)
    if canonical:
        return canonical
    return text if spdx.is_expression(text) else None


def _spelling_key(text: str) -> str:
    return " ".join(text.replace(",", " ").casefold().split())


def _as_name(value: Any) -> Optional[str]:
    """A short declaration worth keeping verbatim, or None for placeholders."""
    text = _single_line(value, _MAX_NAME_LENGTH)
    if text is None:
        return None
    folded = text.casefold()
    if (
        folded in _PLACEHOLDERS
        or folded.startswith(("see ", "copyright"))
        or "://" in folded
        or _LICENSE_FILENAME.match(text)
    ):
        return None
    return text


def normalize_license(info: Any) -> Optional[ResolvedLicense]:
    """The license a PyPI ``info`` object declares, or None. Never raises."""
    if not isinstance(info, Mapping):
        return None

    expression = _as_spdx(info.get("license_expression"), _MAX_EXPRESSION_LENGTH)
    if expression:
        return ResolvedLicense(expression, is_spdx=True)

    field = info.get("license")
    as_spdx = _as_spdx(field, _MAX_EXPRESSION_LENGTH)
    if as_spdx:
        return ResolvedLicense(as_spdx, is_spdx=True)

    name = _as_name(field)
    if name and _spelling_key(name) in _SPELLINGS:
        return ResolvedLicense(_SPELLINGS[_spelling_key(name)], is_spdx=True)

    classifiers = info.get("classifiers")
    if isinstance(classifiers, list):
        # Every license classifier counts, including ones this table cannot
        # map: MIT beside a generic "BSD License" may be dual licensing, and
        # dropping the unmapped one before counting would report plain MIT.
        # Two license classifiers could mean a choice, a combination or a stale
        # leftover, so any more than one resolves nothing.
        declared = {
            c for c in classifiers
            if isinstance(c, str) and c.startswith("License ::")
            and c not in _CATEGORY_CLASSIFIERS
        }
        if len(declared) == 1:
            (only,) = declared
            if only in _CLASSIFIERS:
                return ResolvedLicense(_CLASSIFIERS[only], is_spdx=True)

    if name:
        return ResolvedLicense(name, is_spdx=False)
    return None


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------

class _Cache:
    def __init__(self, directory: Optional[Path], now: float):
        self.path = directory / CACHE_FILENAME if directory else None
        self.now = now
        self.entries: Dict[str, Dict[str, Any]] = {}
        # Only a run that fetched something writes: a CI job whose every pin
        # is cached should not rewrite a shared home directory's file.
        self.dirty = False
        self._load()

    def _load(self) -> None:
        if self.path is None:
            return
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return
        if not isinstance(data, dict) or data.get("schema") != _CACHE_SCHEMA:
            return
        if isinstance(data.get("entries"), dict):
            self.entries = data["entries"]

    def _fresh(self, entry: Any) -> bool:
        try:
            ttl = RESOLVED_TTL_SECONDS if entry.get("license") else UNRESOLVED_TTL_SECONDS
            return self.now - float(entry["fetched_at"]) < ttl
        except (AttributeError, TypeError, KeyError, ValueError):
            return False

    def get(self, key: str) -> Tuple[bool, Optional[ResolvedLicense]]:
        """(hit, license). A hit with no license is a cached unknown."""
        entry = self.entries.get(key)
        if not self._fresh(entry):
            return False, None
        value = entry.get("license")
        if value is None:
            return True, None
        if isinstance(value, str) and isinstance(entry.get("is_spdx"), bool):
            return True, ResolvedLicense(value, entry["is_spdx"])
        return False, None

    def put(self, key: str, resolved: Optional[ResolvedLicense]) -> None:
        self.entries[key] = {
            "fetched_at": self.now,
            "license": resolved.value if resolved else None,
            "is_spdx": resolved.is_spdx if resolved else False,
        }
        self.dirty = True

    def save(self) -> None:
        """Write-tmp-then-rename, dropping expired entries. Never raises."""
        if self.path is None or not self.dirty:
            return
        payload = {
            "schema": _CACHE_SCHEMA,
            "entries": {k: v for k, v in self.entries.items() if self._fresh(v)},
        }
        tmp = self.path.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps(payload, separators=(",", ":")))
            tmp.replace(self.path)
        except OSError:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass


def _default_session() -> Any:
    """The HTTP client used when none is injected. A seam the test suite stubs."""
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=1, pool_maxsize=_FETCH_WORKERS
    )
    session.mount("https://", adapter)
    return session


def _default_cache_dir() -> Optional[Path]:
    # Imported lazily so tests that stub telemetry's config dir apply here too.
    from . import telemetry

    return telemetry.get_config_dir()


# --------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------

class _Client:
    def __init__(self, session: Any, budget_seconds: float):
        self.session = session
        self.deadline = time.monotonic() + budget_seconds
        self.headers = {"User-Agent": f"aisbom-cli/{_tool_version()}"}

    def _timeout(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise PyPIUnavailable("PyPI lookup exceeded its time budget")
        return min(REQUEST_TIMEOUT_SECONDS, remaining)

    def _pause(self, seconds: float) -> None:
        if self.deadline - time.monotonic() <= seconds:
            raise PyPIUnavailable("PyPI lookup exceeded its time budget")
        time.sleep(seconds)

    def release_info(self, name: str, version: str) -> Optional[Dict[str, Any]]:
        """The ``info`` object for one release, or None when PyPI has no such
        release. Retries transient failures only; raises when there is no
        answer to give."""
        url = f"{PYPI_API}/{quote(name, safe='')}/{quote(version, safe='')}/json"
        for attempt in range(_ATTEMPTS):
            last = attempt == _ATTEMPTS - 1
            try:
                response = self.session.get(
                    url, timeout=self._timeout(), headers=self.headers
                )
            except (requests.ConnectionError, requests.Timeout):
                if last:
                    raise
            else:
                if response.status_code == 404:
                    return None
                if response.status_code in _RETRYABLE_STATUS and not last:
                    pass
                else:
                    response.raise_for_status()
                    try:
                        payload = response.json()
                    except ValueError as exc:
                        raise PyPIUnavailable(
                            f"PyPI returned a malformed response for {name}"
                        ) from exc
                    info = payload.get("info") if isinstance(payload, dict) else None
                    if not isinstance(info, dict):
                        raise PyPIUnavailable(
                            f"PyPI returned a malformed response for {name}"
                        )
                    return info
            self._pause(_BACKOFF_SECONDS * (attempt + 1))
        raise PyPIUnavailable("PyPI retries exhausted")  # pragma: no cover - loop returns or raises


def _describe(exc: BaseException) -> str:
    if isinstance(exc, PyPIUnavailable):
        return str(exc)
    if isinstance(exc, requests.RequestException):
        return f"PyPI request failed ({type(exc).__name__})"
    return f"PyPI lookup failed ({type(exc).__name__})"


def resolve_dependency_licenses(
    dependencies: Sequence[Dict[str, Any]],
    *,
    session: Any = None,
    cache_dir: Any = _DEFAULT_CACHE_DIR,
    now: Optional[float] = None,
    budget_seconds: float = LOOKUP_BUDGET_SECONDS,
) -> LicenseLookupResult:
    """Record PyPI-declared licenses on a scan's dependencies. Never raises.

    Each resolved dependency gains ``license``, ``license_is_spdx`` and
    ``license_source``; every other dependency is left exactly as it was.
    """
    result = LicenseLookupResult()
    targets: List[Tuple[Dict[str, Any], str, str]] = []
    for dep in dependencies:
        if not dep.get("pinned"):
            result.skipped_unpinned += 1
            continue
        targets.append((dep, canonicalize_name(str(dep["name"])), str(dep["version"])))
    result.queried = len(targets)
    if not targets:
        return result

    directory = _default_cache_dir() if cache_dir is _DEFAULT_CACHE_DIR else cache_dir
    cache = _Cache(Path(directory) if directory else None,
                   time.time() if now is None else now)

    answers: Dict[Tuple[str, str], Optional[ResolvedLicense]] = {}
    failures: Dict[Tuple[str, str], str] = {}
    try:
        uncached = []
        for pin in dict.fromkeys((name, version) for _, name, version in targets):
            hit, resolved = cache.get(f"{pin[0]}=={pin[1]}")
            if hit:
                answers[pin] = resolved
            else:
                uncached.append(pin)

        if uncached:
            client = _Client(
                session if session is not None else _default_session(), budget_seconds
            )

            def fetch(pin: Tuple[str, str]) -> Optional[ResolvedLicense]:
                return normalize_license(client.release_info(*pin))

            with ThreadPoolExecutor(max_workers=min(_FETCH_WORKERS, len(uncached))) as pool:
                futures = {pin: pool.submit(fetch, pin) for pin in uncached}
            for pin, future in futures.items():
                try:
                    answers[pin] = future.result()
                except Exception as exc:  # noqa: BLE001 - one package, not the scan
                    failures[pin] = _describe(exc)
                    continue
                cache.put(f"{pin[0]}=={pin[1]}", answers[pin])
    except Exception as exc:  # noqa: BLE001 - enrichment must never break a scan
        for _, name, version in targets:
            if (name, version) not in answers:
                failures.setdefault((name, version), _describe(exc))
    finally:
        cache.save()

    for dep, name, version in targets:
        pin = (name, version)
        if pin in failures:
            result.failed += 1
            continue
        resolved = answers.get(pin)
        if resolved is None:
            continue
        dep["license"] = resolved.value
        dep["license_is_spdx"] = resolved.is_spdx
        dep["license_source"] = LICENSE_SOURCE
        result.resolved += 1

    if failures:
        reason = next(iter(failures.values()))
        result.error = (
            f"PyPI license lookup failed for {result.failed} of "
            f"{result.queried} pinned dependenc"
            f"{'y' if result.queried == 1 else 'ies'} ({reason})"
        )
    return result
