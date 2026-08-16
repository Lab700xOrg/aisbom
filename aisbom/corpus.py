"""
Bypass regression corpus + scorecard harness.

A reproducible test corpus of publicly-documented pickle/model-scanner evasion
techniques, and a harness that scans each one with AIsbom's own scanner and
records whether the payload was caught. It exists so that:

* detection hardening has a fixed target to improve against,
* regressions in detection fail loudly (``tests/corpus/baseline.json``), and
* the public "Does AIsbom catch it?" scorecard is generated from a real run
  rather than hand-written claims.

**Nothing here is live malware.** Every artifact is synthesized from
``mock_generator``'s inert primitives, and each one names the same harmless
``echo`` string. The corpus is only ever *disassembled*, never unpickled —
``score_corpus`` asserts that by trapping ``pickle.load``/``pickle.loads`` for
the duration of the run.

Each case declares an ``expected`` verdict — what a correct scanner *should*
do — which is deliberately not the same thing as the current baseline. The gap
between the two is the scorecard.
"""

from __future__ import annotations

import json
import pickle
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

from aisbom.mock_generator import (
    HARMLESS_COMMAND,
    harmless_reduce_pickle,
    harmless_stack_global_pickle,
    pytorch_zip_bytes,
    truncate_pickle,
)
from aisbom.scanner import DeepScanner

__all__ = [
    "CASES",
    "HARMLESS_COMMAND",
    "VERDICT_RANK",
    "BypassCase",
    "GeneratedCase",
    "check_floor",
    "generate_corpus",
    "is_control",
    "iter_files",
    "merge_floor",
    "render_baseline",
    "render_floor",
    "render_markdown",
    "score_corpus",
    "strip_generated_stamp",
]


class CorpusDependencyError(RuntimeError):
    """Raised when a corpus case needs a dev-only dependency that is missing."""


# --- ZIP tampering helpers --------------------------------------------------
# The Sonatype and JFrog bypasses are container-level, not opcode-level: the
# pickle is perfectly ordinary, but the ZIP around it is malformed in a way
# PyTorch tolerates and a scanner does not. These reproduce that asymmetry by
# patching a well-formed archive after the fact.


def _tamper_first_filename(blob: bytes, name: str, replacement: str) -> bytes:
    """
    Rewrite the filename in the *local* file header only, leaving the central
    directory pointing at the original name (CVE-2025-1944).

    Local headers precede the central directory, so the first occurrence is the
    local one. Replacement must be the same length to keep offsets valid.
    """
    if len(name) != len(replacement):
        raise ValueError("replacement must preserve the filename length")
    index = blob.find(name.encode("utf-8"))
    if index == -1:
        raise ValueError(f"{name!r} not found in archive")
    return blob[:index] + replacement.encode("utf-8") + blob[index + len(name):]


def _set_local_header_flags(blob: bytes, flags: int) -> bytes:
    """Set the general-purpose bit flag in the first local header (CVE-2025-1945)."""
    index = blob.find(b"PK\x03\x04")
    if index == -1:
        raise ValueError("no local file header found")
    offset = index + 6
    return blob[:offset] + flags.to_bytes(2, "little") + blob[offset + 2:]


def _corrupt_central_crc(blob: bytes) -> bytes:
    """
    Flip the stored CRC-32 of the first central-directory entry (CVE-2025-10156).

    PyTorch disables CRC validation when loading; Python's zipfile does not, so
    it raises on read while the model still loads fine for the victim.
    """
    index = blob.find(b"PK\x01\x02")
    if index == -1:
        raise ValueError("no central directory header found")
    offset = index + 16
    original = blob[offset:offset + 4]
    corrupted = bytes([original[0] ^ 0xFF]) + original[1:]
    return blob[:offset] + corrupted + blob[offset + 4:]


# --- case builders ----------------------------------------------------------
# Each builder writes its artifacts into a per-case directory and returns None;
# the directory is what gets scanned, so a case can be one file or several.


def _write(directory: Path, name: str, blob: bytes) -> None:
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)


def _build_control(directory: Path) -> None:
    _write(directory, "model.pt", pytorch_zip_bytes(harmless_reduce_pickle("os", "system")))


def _build_benign(directory: Path) -> None:
    """A real, ordinary model: only allowlisted globals, no dangerous sinks."""
    payload = pickle.dumps({"state_dict": {"layer.weight": [0.1, 0.2]}}, protocol=2)
    _write(directory, "model.pt", pytorch_zip_bytes(payload))


def _build_nullifai_7z(directory: Path) -> None:
    try:
        import py7zr
    except ImportError as exc:  # pragma: no cover - exercised only without dev deps
        raise CorpusDependencyError(
            "the nullifAI 7z case needs py7zr; install the dev group with "
            "`poetry install --with dev`"
        ) from exc

    payload = harmless_reduce_pickle("os", "system")
    with py7zr.SevenZipFile(directory / "model.pt", "w") as archive:
        archive.writestr(payload, "archive/data.pkl")
        archive.writestr("3", "archive/version")


def _build_nullifai_broken_stream(directory: Path) -> None:
    broken = truncate_pickle(harmless_reduce_pickle("os", "system"))
    _write(directory, "model.pt", pytorch_zip_bytes(broken))


def _build_pip_main(directory: Path) -> None:
    _write(directory, "model.pt", pytorch_zip_bytes(harmless_reduce_pickle("pip", "main")))


def _build_nonstandard_extension(directory: Path) -> None:
    """
    The payload lives in `config.p`, an extension the scanner does not consider
    a model file, so it is never opened at all (CVE-2025-1889).
    """
    _write(directory, "config.p", harmless_reduce_pickle("os", "system"))


def _build_zip_filename_tamper(directory: Path) -> None:
    blob = pytorch_zip_bytes(harmless_reduce_pickle("os", "system"))
    _write(directory, "model.pt", _tamper_first_filename(blob, "archive/data.pkl", "archive/data_pkl"))


def _build_zip_flag_bits(directory: Path) -> None:
    blob = pytorch_zip_bytes(harmless_reduce_pickle("os", "system"))
    # Bit 3 = sizes deferred to a trailing data descriptor.
    _write(directory, "model.pt", _set_local_header_flags(blob, 0x08))


def _build_extension_confusion(directory: Path) -> None:
    """A bare pickle wearing a PyTorch extension — no ZIP container at all."""
    _write(directory, "model.bin", harmless_reduce_pickle("os", "system"))


def _build_zip_crc(directory: Path) -> None:
    blob = pytorch_zip_bytes(harmless_reduce_pickle("os", "system"), compression=zipfile.ZIP_STORED)
    _write(directory, "model.pt", _corrupt_central_crc(blob))


def _build_asyncio_subclass(directory: Path) -> None:
    payload = harmless_reduce_pickle("asyncio.unix_events", "_UnixSubprocessTransport")
    _write(directory, "model.pt", pytorch_zip_bytes(payload))


def _build_bdb_gadget(directory: Path) -> None:
    _write(directory, "model.pt", pytorch_zip_bytes(harmless_reduce_pickle("bdb", "Bdb")))


def _build_shadowpickle(directory: Path) -> None:
    """
    Every global is on the allowlist (`collections.OrderedDict`), reached via
    STACK_GLOBAL rather than GLOBAL — the shape ShadowPickle uses to shadow a
    trusted builtin that appears in essentially every scanner's allowlist.
    """
    payload = harmless_stack_global_pickle("collections", "OrderedDict")
    _write(directory, "model.pt", pytorch_zip_bytes(payload))


@dataclass(frozen=True)
class BypassCase:
    """One documented evasion technique, its citation, and its ideal verdict."""

    id: str
    title: str
    evasion_class: str
    source: str
    source_url: str
    description: str
    builder: Callable[[Path], None]
    expected: str = "detected"
    malicious: bool = True
    # Why this case is currently not fully caught, for cases that aren't.
    # Deliberately does *not* change `expected`: every evasion technique here
    # remains one a correct scanner should catch, so the gate keeps counting it
    # against us. This field explains a gap; it never excuses one.
    limitation: str | None = None


@dataclass(frozen=True)
class GeneratedCase:
    case: BypassCase
    path: Path


CASES: tuple[BypassCase, ...] = (
    BypassCase(
        id="control-os-system-zip",
        title="Plain os.system in a standard PyTorch ZIP",
        evasion_class="control",
        source="AIsbom control case (no evasion)",
        source_url="https://github.com/Lab700xOrg/aisbom",
        description=(
            "No evasion at all: the reference case every scanner must catch. If this "
            "one ever misses, the harness is broken and the rest of the table is noise."
        ),
        builder=_build_control,
    ),
    BypassCase(
        id="benign-allowlisted-globals",
        title="Ordinary model, allowlisted globals only",
        evasion_class="control",
        source="AIsbom control case (false-positive guard)",
        source_url="https://github.com/Lab700xOrg/aisbom",
        description=(
            "A normal state_dict with no dangerous sinks. Guards the other direction: "
            "a scanner that flags everything is as useless as one that flags nothing."
        ),
        builder=_build_benign,
        expected="clean",
        malicious=False,
    ),
    BypassCase(
        id="nullifai-7z-container",
        title="Model packed with 7z instead of ZIP",
        evasion_class="container-format",
        source="ReversingLabs — nullifAI (malicious models on Hugging Face)",
        source_url="https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face",
        description=(
            "PyTorch's default container is ZIP; packing the same payload with 7z "
            "meant picklescan never opened it, while the model still loaded."
        ),
        builder=_build_nullifai_7z,
        limitation=(
            "AIsbom reports `CRITICAL (Non-Standard Container: 7z)` — the right severity, "
            "but earned from the container rather than the payload. The archive is named, "
            "never unpacked, so the `os.system` call inside is never disassembled and the "
            "reported reason is not the real one. Unpacking 7z would mean a native "
            "dependency in every install to cover one evasion class, which is not a "
            "trade worth making; a user acting on this verdict is nonetheless correctly "
            "warned off the file."
        ),
    ),
    BypassCase(
        id="nullifai-broken-stream",
        title="Deliberately broken pickle stream, payload first",
        evasion_class="broken-stream",
        source="ReversingLabs — nullifAI (malicious models on Hugging Face)",
        source_url="https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face",
        description=(
            "The reverse shell sits at the front of the stream and the tail is corrupt. "
            "The pickle VM executes sequentially, so the payload runs before the error; "
            "a scanner that requires a well-formed stream bails out first."
        ),
        builder=_build_nullifai_broken_stream,
    ),
    BypassCase(
        id="cve-2025-1716-pip-main",
        title="Code execution via pip.main()",
        evasion_class="unlisted-global",
        source="Sonatype — CVE-2025-1716",
        source_url="https://www.sonatype.com/security-advisories/cve-2025-1716",
        description=(
            "Reaches execution through a global nobody thought to blocklist: pip.main() "
            "installs an attacker-controlled package. Fixed in picklescan 0.0.21."
        ),
        builder=_build_pip_main,
    ),
    BypassCase(
        id="cve-2025-1889-nonstandard-extension",
        title="Payload in a file with a non-standard extension",
        evasion_class="file-extension",
        source="Sonatype — CVE-2025-1889",
        source_url="https://www.sonatype.com/security-advisories/cve-2025-1889",
        description=(
            "The pickle is named config.p. Extension-driven discovery never opens it, "
            "so nothing is scanned. Fixed in picklescan 0.0.22."
        ),
        builder=_build_nonstandard_extension,
        limitation=(
            "The only outright miss in the corpus: the scan reports `No AI models found` "
            "and emits zero artifacts, so a user gets a clean run on a file carrying a "
            "payload. Nothing subtle blocks this — discovery is extension-driven and "
            "`.p` is not on the list. picklescan closed it in 0.0.22 and AIsbom has not, "
            "which is precisely why the case stays on the scorecard at "
            "`expected=detected`."
        ),
    ),
    BypassCase(
        id="cve-2025-1944-zip-filename-tamper",
        title="ZIP local-header filename differs from the central directory",
        evasion_class="zip-tampering",
        source="Sonatype — CVE-2025-1944",
        source_url="https://www.sonatype.com/security-advisories/cve-2025-1944",
        description=(
            "The two copies of the filename disagree. PyTorch loads it; a strict ZIP "
            "reader raises and the scan is abandoned. Fixed in picklescan 0.0.23."
        ),
        builder=_build_zip_filename_tamper,
    ),
    BypassCase(
        id="cve-2025-1945-zip-flag-bits",
        title="ZIP general-purpose flag bits modified",
        evasion_class="zip-tampering",
        source="Sonatype — CVE-2025-1945",
        source_url="https://www.sonatype.com/security-advisories/cve-2025-1945",
        description=(
            "Flipping flag bits in the local header changes how the archive is parsed "
            "without changing what PyTorch loads. Fixed in picklescan 0.0.23."
        ),
        builder=_build_zip_flag_bits,
    ),
    BypassCase(
        id="cve-2025-10155-extension-confusion",
        title="Bare pickle wearing a PyTorch extension",
        evasion_class="file-extension",
        source="JFrog — CVE-2025-10155",
        source_url="https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/",
        description=(
            "A raw pickle named model.bin. The PyTorch parser fails because there is no "
            "ZIP container, while PyTorch itself identifies the file by content. "
            "Fixed in picklescan 0.0.31."
        ),
        builder=_build_extension_confusion,
    ),
    BypassCase(
        id="cve-2025-10156-zip-crc",
        title="Corrupted CRC-32 in the ZIP archive",
        evasion_class="zip-tampering",
        source="JFrog — CVE-2025-10156",
        source_url="https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/",
        description=(
            "PyTorch disables CRC checking by default; a scanner that validates CRC "
            "errors out and scans nothing. Fixed in picklescan 0.0.31."
        ),
        builder=_build_zip_crc,
    ),
    BypassCase(
        id="cve-2025-10157-asyncio-subclass",
        title="Dangerous import reached through an asyncio submodule",
        evasion_class="gadget-import",
        source="JFrog — CVE-2025-10157",
        source_url="https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/",
        description=(
            "Uses a submodule rather than the exact blocklisted module name, so an "
            "exact-match unsafe-globals check downgrades it. Fixed in picklescan 0.0.31."
        ),
        builder=_build_asyncio_subclass,
    ),
    BypassCase(
        id="checkmarx-bdb-gadget",
        title="Indirect execution via bdb.Bdb.run",
        evasion_class="gadget-import",
        source="Checkmarx — Free Hugs: What to be Wary of in Hugging Face (Part 4)",
        source_url="https://checkmarx.com/blog/free-hugs-what-to-be-wary-of-in-hugging-face-part-4/",
        description=(
            "`bdb` is Python's built-in debugger and `Bdb.run` is equivalent to `exec`. "
            "A benign-looking module with an execution sink: no obviously dangerous "
            "name appears anywhere in the stream, which is the point of a gadget."
        ),
        builder=_build_bdb_gadget,
    ),
    BypassCase(
        id="shadowpickle-allowlist-overwrite",
        title="Allowlisted builtin reached via STACK_GLOBAL",
        evasion_class="allowlist-abuse",
        source="ShadowPickle (arXiv 2607.17503)",
        source_url="https://arxiv.org/html/2607.17503",
        description=(
            "Overwrites collections.OrderedDict — a name on essentially every scanner's "
            "allowlist — and resolves it via STACK_GLOBAL rather than an inline GLOBAL "
            "argument, so string-matching on the opcode argument sees nothing."
        ),
        builder=_build_shadowpickle,
        limitation=(
            "AIsbom does resolve STACK_GLOBAL and reads the pair off the stack, so it "
            "sees `collections.OrderedDict` — and that name is legitimately allowlisted, "
            "because real state_dicts are OrderedDicts. Both modes therefore return only "
            "`MEDIUM (Pickle Present)`, the baseline every pickle gets, rather than a "
            "signal specific to this file. This is the ceiling on static allowlist "
            "analysis: the call is indistinguishable from a legitimate call to an "
            "allowlisted global, and flagging the shape would flag ordinary checkpoints. "
            "Closing it needs evidence beyond the resolved name — argument shape, or "
            "provenance — not a new entry on a blocklist."
        ),
    ),
)


def is_control(case: BypassCase) -> bool:
    """Controls calibrate the harness; they are not evasion techniques."""
    return case.evasion_class == "control"


def iter_files(path: Path) -> Iterator[Path]:
    """Every file belonging to a case (cases may be a directory of files)."""
    if path.is_file():
        yield path
        return
    for child in sorted(path.rglob("*")):
        if child.is_file():
            yield child


def generate_corpus(target_dir: Path) -> list[GeneratedCase]:
    """Materialize every case into its own directory under ``target_dir``."""
    target_dir = Path(target_dir)
    generated: list[GeneratedCase] = []
    for case in CASES:
        case_dir = target_dir / case.id
        case_dir.mkdir(parents=True, exist_ok=True)
        case.builder(case_dir)
        generated.append(GeneratedCase(case=case, path=case_dir))
    return generated


def _classify(artifacts: list[dict], malicious: bool) -> str:
    """
    Reduce a scan result to one of: detected / partial / missed / clean / false-positive.

    "partial" is the honest middle: the scanner refused to call the file safe,
    but never disassembled the payload, so it reports the wrong reason. That
    distinction is the whole point of publishing the scorecard.
    """
    named_threat = any(
        "RCE Detected" in artifact.get("risk_level", "")
        or "UNSAFE_IMPORT" in artifact.get("risk_level", "")
        for artifact in artifacts
    )
    if not malicious:
        return "false-positive" if named_threat else "clean"
    if named_threat:
        return "detected"
    flagged = any(
        artifact.get("risk_level", "").startswith(("CRITICAL", "MEDIUM"))
        for artifact in artifacts
    )
    return "partial" if flagged else "missed"


def score_corpus(generated: list[GeneratedCase]) -> dict:
    """
    Scan every case in both blocklist and strict mode.

    ``pickle.load``/``pickle.loads`` are trapped for the duration so the result
    carries proof that scoring is pure static analysis — a corpus harness that
    could execute its own corpus would be worse than no harness.
    """
    unpickle_calls: list[str] = []
    real_loads, real_load = pickle.loads, pickle.load

    def _trap_loads(*args, **kwargs):
        unpickle_calls.append("pickle.loads")
        raise AssertionError("corpus scoring must never unpickle an artifact")

    def _trap_load(*args, **kwargs):
        unpickle_calls.append("pickle.load")
        raise AssertionError("corpus scoring must never unpickle an artifact")

    pickle.loads, pickle.load = _trap_loads, _trap_load
    try:
        scored: dict[str, dict] = {}
        for item in generated:
            row: dict[str, object] = {}
            for mode, strict in (("blocklist", False), ("strict", True)):
                results = DeepScanner(str(item.path), strict_mode=strict).scan()
                row[mode] = _classify(results["artifacts"], item.case.malicious)
            scored[item.case.id] = row
    finally:
        pickle.loads, pickle.load = real_loads, real_load

    return {"executed": bool(unpickle_calls), "cases": scored}


# --- the ratchet ------------------------------------------------------------
# baseline.json records what detection *is*; floor.json records the best it has
# ever been. The baseline is regenerated freely — it is a description. The floor
# is a promise: once a case is caught, it stays caught. Ordering these lets the
# test say "worse than before" rather than merely "different from before", which
# is the difference between a ratchet and a rubber stamp.
VERDICT_RANK = {
    "missed": 0,
    "false-positive": 0,
    "partial": 1,
    "detected": 2,
    "clean": 2,
}


def merge_floor(results: dict, existing: dict | None = None) -> dict:
    """
    Raise the floor to the current verdicts. Never lowers it.

    A regression therefore cannot be absorbed by regenerating: the floor keeps
    the old, better value, and the check keeps failing until detection is fixed
    or a human edits floor.json by hand — which shows up in review.
    """
    previous = (existing or {}).get("cases", {})
    merged: dict[str, dict[str, str]] = {}
    for case_id, modes in results["cases"].items():
        merged[case_id] = {}
        for mode, verdict in modes.items():
            best = previous.get(case_id, {}).get(mode)
            if best and VERDICT_RANK[best] > VERDICT_RANK[verdict]:
                merged[case_id][mode] = best
            else:
                merged[case_id][mode] = verdict
    return {"cases": merged}


def check_floor(results: dict, floor: dict) -> list[dict]:
    """Return every case that now scores below the floor. Empty means green."""
    regressions = []
    for case_id, modes in floor.get("cases", {}).items():
        current_modes = results["cases"].get(case_id)
        if current_modes is None:
            regressions.append(
                {"case": case_id, "mode": "-", "floor": "present", "current": "missing"}
            )
            continue
        for mode, required in modes.items():
            current = current_modes.get(mode, "missed")
            if VERDICT_RANK[current] < VERDICT_RANK[required]:
                regressions.append(
                    {"case": case_id, "mode": mode, "floor": required, "current": current}
                )
    return regressions


_VERDICT_LABEL = {
    "detected": "✅ detected",
    "partial": "⚠️ partial",
    "missed": "❌ missed",
    "clean": "✅ clean",
    "false-positive": "❌ false positive",
}


def strip_generated_stamp(text: str) -> str:
    """Drop the generated-by banner so staleness checks compare content only."""
    return "\n".join(
        line for line in text.splitlines() if not line.startswith("_Generated by")
    ).strip()


def render_markdown(results: dict) -> str:
    """Render the human-readable scorecard published by the /blog article."""
    cases = results["cases"]
    evasions = [c for c in CASES if not is_control(c)]
    controls = [c for c in CASES if is_control(c)]

    detected = sum(1 for c in evasions if cases[c.id]["blocklist"] == "detected"
                   or cases[c.id]["strict"] == "detected")

    lines = [
        "# Does AIsbom catch it? — pickle-evasion scorecard",
        "",
        "_Generated by `aisbom bypass-scorecard` — do not edit by hand._",
        "",
        "Every row is a publicly-documented technique for smuggling a malicious pickle",
        "past a model scanner, reproduced here as an inert artifact and scanned with",
        "AIsbom's own engine. Artifacts are synthesized, never copied from live malware,",
        "and are only ever disassembled — no pickle in this corpus is executed.",
        "",
        f"**{detected} of {len(evasions)}** evasion cases are caught in at least one scan mode.",
        "",
        "`blocklist` is the default mode (flag known-dangerous globals); `strict` is",
        "`--strict` (allowlist — anything unrecognized is flagged). A ⚠️ partial means",
        "AIsbom refused to call the file safe but never disassembled the payload, so it",
        "reports the wrong reason.",
        "",
        "## Scorecard",
        "",
        "| Case | Evasion class | Blocklist | Strict | Source |",
        "| --- | --- | --- | --- | --- |",
    ]
    for case in evasions:
        row = cases[case.id]
        lines.append(
            f"| `{case.id}`<br>{case.title} | {case.evasion_class} "
            f"| {_VERDICT_LABEL[row['blocklist']]} | {_VERDICT_LABEL[row['strict']]} "
            f"| [{case.source}]({case.source_url}) |"
        )

    lines += ["", "## Controls", "", "| Case | Blocklist | Strict |", "| --- | --- | --- |"]
    for case in controls:
        row = cases[case.id]
        lines.append(
            f"| `{case.id}`<br>{case.title} "
            f"| {_VERDICT_LABEL[row['blocklist']]} | {_VERDICT_LABEL[row['strict']]} |"
        )

    lines += ["", "## Case detail", ""]
    for case in CASES:
        lines += [
            f"### `{case.id}` — {case.title}",
            "",
            f"**Evasion class:** {case.evasion_class}  ",
            f"**Source:** [{case.source}]({case.source_url})  ",
            f"**A correct scanner should:** {case.expected}",
            "",
            case.description,
            "",
        ]
        if case.limitation:
            lines += [f"**Current limitation:** {case.limitation}", ""]

    return "\n".join(lines).rstrip() + "\n"


def render_baseline(results: dict) -> str:
    """Serialize the regression baseline committed at tests/corpus/baseline.json."""
    return json.dumps({"cases": results["cases"]}, indent=2, sort_keys=True) + "\n"


def render_floor(floor: dict) -> str:
    """Serialize the ratchet committed at tests/corpus/floor.json."""
    return json.dumps(floor, indent=2, sort_keys=True) + "\n"
