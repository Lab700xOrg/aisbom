"""OSV lookup for pinned requirements.txt dependencies — CVE-keyed VEX (#128).

The finding-class statements in :mod:`aisbom.vex` describe content inside model
files, which has no CVE. The ``requirements.txt`` pins in the same scan are the
part where real CVEs do exist, and this module supplies statements for them:
it asks OSV which advisories cover each exact pin and turns the confirmed ones
into :class:`~aisbom.vex.VexStatement` objects the existing emitters serialize
unchanged.

Contract
--------

**Enrichment, never the scan.** Every failure — no network, a timeout, a
malformed response, a record OSV cannot return, an exhausted time budget —
degrades to *no CVE statements* plus a reason string. Nothing here raises into
the CLI, changes an exit code, or touches the model findings. This is the same
asymmetry as the HF model-card fetch (#111), and it is what keeps the
air-gapped workflow working with no flag at all. A partial answer is treated as
no answer: a document listing some of a dependency's advisories reads as the
complete list, which is worse than an honest omission.

**Only exact pins are looked up.** ``torch>=2.0`` does not say which version is
installed, so any statement about "2.0" might be about a version nobody runs.
Range specifiers are counted and reported, never queried.

**OSV shortlists, a local check confirms.** ``/v1/querybatch`` names the
advisories OSV believes cover a name + version; each full record is then
re-evaluated here against its ``versions`` list and ``ECOSYSTEM`` ranges using
PEP 440 ordering. Agreement is ``affected``. Where the local check disagrees or
cannot evaluate the record (a ``GIT``-only range, an unparseable version), the
statement is ``under_investigation`` — never silently dropped, and never
asserted as ``affected`` on one opinion.

**No negative statements.** "No known advisory" is not
``vulnerable_code_not_present``, and AIsbom never observes whether vulnerable
dependency code is reachable, so dependencies only ever receive ``affected``
or ``under_investigation``.

**Cached on disk.** A CI job scanning the same ``requirements.txt`` on every
push must not hit OSV every time. Answers (hits *and* misses) live in
``~/.aisbom/osv_cache.json`` for :data:`CACHE_TTL_SECONDS`. An unwritable
config directory just means no cache.

PyInstaller constraint: ``requests`` and ``packaging`` only, both already
bundled.
"""

from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import requests
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .modelcard import dependency_bom_ref
from .spdx_gen import _tool_version
from .vex import (
    STATUS_AFFECTED,
    STATUS_UNDER_INVESTIGATION,
    FindingClass,
    VexStatement,
)

OSV_API = "https://api.osv.dev/v1"
OSV_VULNERABILITY_URL = "https://osv.dev/vulnerability/"
OSV_SOURCE_NAME = "OSV"
ECOSYSTEM = "PyPI"

CACHE_FILENAME = "osv_cache.json"
CACHE_TTL_SECONDS = 24 * 60 * 60
_CACHE_SCHEMA = 1

# Per request, and for the whole lookup. Capped like the model-card fetch: a
# slow OSV must never be what makes a CI scan hang.
REQUEST_TIMEOUT_SECONDS = 10
LOOKUP_BUDGET_SECONDS = 30

# querybatch accepts up to 1000 queries; a requirements.txt is far smaller, but
# chunking keeps a pathological file from being one rejected request.
_BATCH_SIZE = 500
# A package with more advisories than fit one page is followed; this bounds it.
_MAX_PAGES = 10
# Advisory records are fetched concurrently, bounded so a large pin set is
# polite to a free public API rather than a burst of hundreds of requests.
_FETCH_WORKERS = 8
# Transient-failure retry: three attempts in total, with a short linear pause.
_ATTEMPTS = 3
_BACKOFF_SECONDS = 0.5
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

DISABLE_ENV_VAR = "AISBOM_NO_OSV"

_DEFAULT_CACHE_DIR = object()


class OsvUnavailable(Exception):
    """Raised internally for any failure that degrades the lookup."""


@dataclass
class OsvLookupResult:
    statements: List[VexStatement] = field(default_factory=list)
    #: Exact pins the lookup covered.
    queried: int = 0
    #: Dependencies left out because they are not exact pins.
    skipped_unpinned: int = 0
    #: Why the lookup degraded to no statements, or ``None`` if it did not.
    error: Optional[str] = None


def disabled_by_env(environ: Mapping[str, str] = os.environ) -> bool:
    return bool(environ.get(DISABLE_ENV_VAR))


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

def _parse(version: str) -> Version:
    return Version(version)


def _event_version(event: Mapping[str, Any]) -> Tuple[str, Version]:
    for kind in ("introduced", "fixed", "last_affected"):
        if kind in event:
            raw = str(event[kind])
            # "0" is OSV's spelling of "every version before the next event".
            return kind, Version("0") if raw == "0" else _parse(raw)
    raise InvalidVersion(f"unrecognised event {event!r}")  # pragma: no cover - callers filter


def _in_ecosystem_range(events: Sequence[Mapping[str, Any]], version: Version) -> bool:
    """Evaluate one ``ECOSYSTEM`` range per the OSV schema's algorithm.

    Events are applied in version order, not listed order. ``last_affected``
    is inclusive; ``fixed`` is exclusive. ``limit`` only bounds git ranges and
    is ignored. Raises :class:`InvalidVersion` for an event that does not parse,
    which the caller reports as undetermined rather than as unaffected.
    """
    parsed = sorted(
        (_event_version(e) for e in events
         if any(k in e for k in ("introduced", "fixed", "last_affected"))),
        key=lambda kv: kv[1],
    )
    vulnerable = False
    for kind, boundary in parsed:
        if kind == "introduced" and version >= boundary:
            vulnerable = True
        elif kind == "fixed" and version >= boundary:
            vulnerable = False
        elif kind == "last_affected" and version > boundary:
            vulnerable = False
    return vulnerable


def version_affected(record: Mapping[str, Any], name: str, version: str) -> Optional[bool]:
    """Does this OSV record cover ``name == version``?

    ``True`` or ``False`` where a PyPI entry for the package could be evaluated;
    ``None`` where nothing could — no entry for this package, only ``GIT`` or
    ``SEMVER`` ranges, or a version that does not parse. ``None`` is not a
    negative, and callers must not treat it as one.
    """
    wanted = canonicalize_name(name)
    try:
        pin = _parse(version)
    except InvalidVersion:
        return None

    evaluated = False
    for entry in record.get("affected") or []:
        package = entry.get("package") or {}
        if package.get("ecosystem") != ECOSYSTEM:
            continue
        if canonicalize_name(str(package.get("name", ""))) != wanted:
            continue

        for listed in entry.get("versions") or []:
            evaluated = True
            try:
                if _parse(str(listed)) == pin:
                    return True
            except InvalidVersion:
                continue

        for rng in entry.get("ranges") or []:
            if rng.get("type") != "ECOSYSTEM":
                continue
            try:
                if _in_ecosystem_range(rng.get("events") or [], pin):
                    return True
            except InvalidVersion:
                return None
            evaluated = True

    return False if evaluated else None


def vulnerability_ids(record: Mapping[str, Any]) -> Tuple[str, Tuple[str, ...]]:
    """``(primary, aliases)`` — the CVE if the advisory has one, else its OSV id."""
    osv_id = str(record["id"])
    names = [osv_id] + [str(a) for a in record.get("aliases") or []]
    cves = sorted({n for n in names if n.startswith("CVE-")})
    primary = cves[0] if cves else osv_id
    aliases = tuple(sorted({n for n in names if n != primary}))
    return primary, aliases


def _fixed_versions(record: Mapping[str, Any], name: str) -> List[str]:
    wanted = canonicalize_name(name)
    fixed = []
    for entry in record.get("affected") or []:
        package = entry.get("package") or {}
        if canonicalize_name(str(package.get("name", ""))) != wanted:
            continue
        for rng in entry.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event and rng.get("type") == "ECOSYSTEM":
                    fixed.append(str(event["fixed"]))
    return list(dict.fromkeys(fixed))


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------

class _Cache:
    def __init__(self, directory: Optional[Path], now: float):
        self.path = directory / CACHE_FILENAME if directory else None
        self.now = now
        self.queries: Dict[str, Dict[str, Any]] = {}
        self.vulns: Dict[str, Dict[str, Any]] = {}
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
        if isinstance(data.get("queries"), dict):
            self.queries = data["queries"]
        if isinstance(data.get("vulns"), dict):
            self.vulns = data["vulns"]

    def _fresh(self, entry: Any) -> bool:
        try:
            return self.now - float(entry["fetched_at"]) < CACHE_TTL_SECONDS
        except (TypeError, KeyError, ValueError):
            return False

    def query(self, key: str) -> Optional[List[str]]:
        entry = self.queries.get(key)
        if self._fresh(entry) and isinstance(entry.get("ids"), list):
            return [str(i) for i in entry["ids"]]
        return None

    def vuln(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        entry = self.vulns.get(vuln_id)
        if self._fresh(entry) and isinstance(entry.get("record"), dict):
            return entry["record"]
        return None

    def put_query(self, key: str, ids: List[str]) -> None:
        self.queries[key] = {"fetched_at": self.now, "ids": ids}

    def put_vuln(self, vuln_id: str, record: Dict[str, Any]) -> None:
        self.vulns[vuln_id] = {"fetched_at": self.now, "record": record}

    def save(self) -> None:
        """Write-tmp-then-rename, dropping expired entries. Never raises."""
        if self.path is None:
            return
        payload = {
            "schema": _CACHE_SCHEMA,
            "queries": {k: v for k, v in self.queries.items() if self._fresh(v)},
            "vulns": {k: v for k, v in self.vulns.items() if self._fresh(v)},
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
    """The HTTP client used when none is injected. A seam the test suite stubs.

    A pooled ``Session`` rather than bare ``requests``: an old pin can name well
    over a hundred advisories (``django==2.0.0`` plus ``pillow==6.0.0`` is 140),
    and a fresh TLS handshake per record both halves throughput and adds
    connect stalls that eat the time budget. The pool is sized to the worker
    count so parallel fetches do not queue for a connection.
    """
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
            raise OsvUnavailable("OSV lookup exceeded its time budget")
        return min(REQUEST_TIMEOUT_SECONDS, remaining)

    def _call(self, method: str, url: str, **kwargs: Any) -> Any:
        """One request, retried on transient failure, returning parsed JSON.

        OSV sits behind a CDN that occasionally answers a single request with
        a 503 — observed live on 1 of 140 record fetches for a real pin set.
        Without a retry, that one blip would cost every CVE statement in the
        run. Only failures a retry can fix are retried (connection errors,
        timeouts, 429, 5xx); a 404 or a malformed body fails at once. Every
        attempt and every pause draws on the shared budget.
        """
        for attempt in range(_ATTEMPTS):
            last = attempt == _ATTEMPTS - 1
            try:
                response = getattr(self.session, method)(
                    url, timeout=self._timeout(), headers=self.headers, **kwargs
                )
            except (requests.ConnectionError, requests.Timeout):
                if last:
                    raise
            else:
                if response.status_code in _RETRYABLE_STATUS and not last:
                    pass
                else:
                    response.raise_for_status()
                    return response.json()
            self._pause(_BACKOFF_SECONDS * (attempt + 1))
        raise OsvUnavailable("OSV retries exhausted")  # pragma: no cover - loop returns or raises

    def _pause(self, seconds: float) -> None:
        if self.deadline - time.monotonic() <= seconds:
            raise OsvUnavailable("OSV lookup exceeded its time budget")
        time.sleep(seconds)

    def querybatch(self, queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        payload = self._call(
            "post", f"{OSV_API}/querybatch", json={"queries": queries}
        )
        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list) or len(results) != len(queries):
            raise OsvUnavailable("OSV returned a malformed querybatch response")
        return results

    def vulnerability(self, vuln_id: str) -> Dict[str, Any]:
        record = self._call("get", f"{OSV_API}/vulns/{vuln_id}")
        if not isinstance(record, dict) or record.get("id") != vuln_id:
            raise OsvUnavailable(f"OSV returned a malformed record for {vuln_id}")
        return record


def _fetch_records(client: _Client, vuln_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Fetch full advisory records in parallel. All or nothing.

    The first failure cancels whatever has not started and re-raises, so the
    caller degrades exactly as it would for a serial fetch and a partial set of
    records never reaches statement building. Every request still draws its
    timeout from the shared budget, so parallelism cannot stretch the deadline.
    """
    if not vuln_ids:
        return {}
    records: Dict[str, Dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(_FETCH_WORKERS, len(vuln_ids))) as pool:
        futures = {pool.submit(client.vulnerability, v): v for v in vuln_ids}
        try:
            for future in as_completed(futures):
                records[futures[future]] = future.result()
        except BaseException:
            for future in futures:
                future.cancel()
            raise
    return records


def _ids_from(result: Any) -> Tuple[List[str], Optional[str]]:
    if not isinstance(result, dict):
        raise OsvUnavailable("OSV returned a malformed querybatch result")
    ids = []
    for vuln in result.get("vulns") or []:
        if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str):
            raise OsvUnavailable("OSV returned a vulnerability with no id")
        ids.append(vuln["id"])
    token = result.get("next_page_token")
    return ids, token if isinstance(token, str) and token else None


def _query_ids(client: _Client, pins: List[Tuple[str, str]]) -> Dict[Tuple[str, str], List[str]]:
    """Advisory ids OSV reports for each (canonical name, version)."""
    found: Dict[Tuple[str, str], List[str]] = {}
    for start in range(0, len(pins), _BATCH_SIZE):
        chunk = pins[start:start + _BATCH_SIZE]
        pending = [(pin, None) for pin in chunk]
        pages = 0
        while pending:
            pages += 1
            if pages > _MAX_PAGES:
                raise OsvUnavailable("OSV pagination did not terminate")
            queries = []
            for (name, version), token in pending:
                query: Dict[str, Any] = {
                    "package": {"name": name, "ecosystem": ECOSYSTEM},
                    "version": version,
                }
                if token:
                    query["page_token"] = token
                queries.append(query)
            results = client.querybatch(queries)
            next_pending = []
            for (pin, _), result in zip(pending, results):
                ids, token = _ids_from(result)
                found.setdefault(pin, []).extend(ids)
                if token:
                    next_pending.append((pin, token))
            pending = next_pending
    return {pin: list(dict.fromkeys(ids)) for pin, ids in found.items()}


# --------------------------------------------------------------------------
# Statements
# --------------------------------------------------------------------------

def _truncate(text: str, limit: int = 1000) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _statement(
    name: str,
    version: str,
    ref: str,
    records: List[Dict[str, Any]],
) -> VexStatement:
    """One statement for one CVE on one dependency, merging twin OSV records."""
    primary, _ = vulnerability_ids(records[0])
    aliases = sorted({a for r in records for a in vulnerability_ids(r)[1]})
    lead = records[0]
    confirmed = [r for r in records if version_affected(r, name, version) is True]
    status = STATUS_AFFECTED if confirmed else STATUS_UNDER_INVESTIGATION
    source_record = confirmed[0] if confirmed else lead

    summary = str(source_record.get("summary") or "").strip()
    details = str(source_record.get("details") or "").strip()
    fixed = sorted(
        {v for r in records for v in _fixed_versions(r, name)},
        key=lambda v: (Version(v) if _is_version(v) else Version("0"), v),
    )

    if fixed:
        action = (
            f"Upgrade {name} from {version} to a version outside the affected "
            f"range (fixed in: {', '.join(fixed)})."
        )
    else:
        action = (
            f"No fixed version of {name} is published for this advisory. Review "
            "it and consider replacing or isolating the dependency."
        )

    if status == STATUS_AFFECTED:
        notes = (
            f"{name}=={version} is inside the affected range published by OSV "
            f"({source_record['id']}). AIsbom does not observe whether the "
            "vulnerable code is reachable from your application."
        )
    else:
        notes = (
            f"OSV lists {name}=={version} as affected by "
            f"{', '.join(r['id'] for r in records)}, but AIsbom could not confirm "
            "it against the advisory's published version ranges."
        )

    finding = FindingClass(
        id=primary,
        title=_truncate(summary or primary, 200),
        description=_truncate(details or summary or primary),
        action=action,
        formats=frozenset(),
        aliases=tuple(aliases),
        reference_url=f"{OSV_VULNERABILITY_URL}{source_record['id']}",
        source_name=OSV_SOURCE_NAME,
    )
    return VexStatement(
        finding_class=finding,
        product_ref=ref,
        product_id="",
        product_hash=None,
        status=status,
        status_notes=notes,
        action_statement=action if status == STATUS_AFFECTED else None,
    )


def _is_version(value: str) -> bool:
    try:
        Version(value)
    except InvalidVersion:
        return False
    return True


def lookup_dependency_statements(
    dependencies: Sequence[Dict[str, Any]],
    *,
    session: Any = None,
    cache_dir: Any = _DEFAULT_CACHE_DIR,
    now: Optional[float] = None,
    budget_seconds: float = LOOKUP_BUDGET_SECONDS,
) -> OsvLookupResult:
    """CVE-keyed statements for a scan's dependency components. Never raises.

    ``dependencies`` is the scanner's list, in the order the SBOM emits them —
    the index is part of each component's ``bom-ref``.
    """
    result = OsvLookupResult()
    targets: List[Tuple[int, Dict[str, Any], Tuple[str, str]]] = []
    for index, dep in enumerate(dependencies):
        if not dep.get("pinned"):
            result.skipped_unpinned += 1
            continue
        pin = (canonicalize_name(str(dep["name"])), str(dep["version"]))
        targets.append((index, dep, pin))
    result.queried = len(targets)
    if not targets:
        return result

    directory = _default_cache_dir() if cache_dir is _DEFAULT_CACHE_DIR else cache_dir
    cache = _Cache(Path(directory) if directory else None,
                   time.time() if now is None else now)

    try:
        client = _Client(
            session if session is not None else _default_session(), budget_seconds
        )

        unique_pins = list(dict.fromkeys(pin for _, _, pin in targets))
        ids_by_pin: Dict[Tuple[str, str], List[str]] = {}
        uncached = []
        for pin in unique_pins:
            cached = cache.query(f"{pin[0]}=={pin[1]}")
            if cached is None:
                uncached.append(pin)
            else:
                ids_by_pin[pin] = cached
        if uncached:
            fetched = _query_ids(client, uncached)
            for pin in uncached:
                ids_by_pin[pin] = fetched.get(pin, [])

        records: Dict[str, Dict[str, Any]] = {}
        missing = []
        for vuln_id in dict.fromkeys(i for ids in ids_by_pin.values() for i in ids):
            record = cache.vuln(vuln_id)
            if record is None:
                missing.append(vuln_id)
            else:
                records[vuln_id] = record
        for vuln_id, record in _fetch_records(client, missing).items():
            cache.put_vuln(vuln_id, record)
            records[vuln_id] = record

        # Only now is the answer complete; cache query results together so a
        # failure part-way never leaves a pin cached against missing records.
        for pin in uncached:
            cache.put_query(f"{pin[0]}=={pin[1]}", ids_by_pin[pin])

        for index, dep, pin in targets:
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for vuln_id in ids_by_pin[pin]:
                record = records[vuln_id]
                if record.get("withdrawn"):
                    continue
                primary, _ = vulnerability_ids(record)
                grouped.setdefault(primary, []).append(record)
            ref = dependency_bom_ref(index, dep)
            for primary in sorted(grouped):
                result.statements.append(
                    _statement(str(dep["name"]), pin[1], ref, grouped[primary])
                )
    except OsvUnavailable as exc:
        result.statements = []
        result.error = str(exc)
    except requests.RequestException as exc:
        result.statements = []
        result.error = f"OSV request failed ({type(exc).__name__})"
    except Exception as exc:  # noqa: BLE001 - enrichment must never break a scan
        result.statements = []
        result.error = f"OSV lookup failed ({type(exc).__name__})"
    finally:
        cache.save()

    return result
