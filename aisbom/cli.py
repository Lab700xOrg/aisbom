import typer
import json
import os
import tomllib
import importlib.metadata
from enum import Enum
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model import HashAlgorithm, HashType, Property
from cyclonedx.output.json import JsonV1Dot5, JsonV1Dot6
from cyclonedx.factory.license import LicenseFactory
from .mock_generator import create_mock_malware_file, create_mock_restricted_file, create_mock_gguf, create_demo_diff_sboms, create_mock_broken_file
from pathlib import Path
from urllib.parse import urlparse
import importlib.metadata
from .scanner import DeepScanner
from .diff import SBOMDiff
from .properties import build_component_properties

import threading
import time
import uuid
from .version_check import check_latest_version
from . import loop_state
from . import telemetry
import requests

app = typer.Typer()
# highlight=False disables Rich's auto-decoration of numbers/paths/IPs in
# plain f-strings. Without it, things like "aisbom 1.0.3" or "v1.6" get
# partial cyan coloring that looks like markup bugs.
console = Console(highlight=False)
# Fetch-failure messages (#58) go to stderr so they don't pollute piped stdout
# (SBOM JSON, markdown) and survive `aisbom scan … > out.json`.
err_console = Console(stderr=True, highlight=False)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Print the installed version and exit.",
        is_eager=True,
    ),
):
    """
    AIsbom — AI Supply Chain Security Scanner.

    Deep introspection of ML model artifacts (.pt, .safetensors, .gguf) for
    malware, license risk, and silent drift. Run `aisbom` with no args to see
    a working example, or `aisbom <command> --help` for details on each command.

    Environment variables:

      AISBOM_NO_TELEMETRY=1   Disable all anonymous usage telemetry. Honored on
                              every code path; never overridden.
    """
    # Order matters: --version wins over the no-args panel so that
    # `aisbom --version` is short and scriptable.
    if version:
        try:
            ver = importlib.metadata.version("aisbom-cli")
        except importlib.metadata.PackageNotFoundError:
            ver = "unknown (dev build)"
        console.print(f"aisbom {ver}")
        raise typer.Exit(code=0)

    # Owns the no-args codepath. When the user runs `aisbom` with no
    # subcommand, show a one-screen quickstart instead of Typer's auto-help
    # block. `--help` still short-circuits to Typer's full reference, and
    # subcommand invocations fall through (this callback is a no-op when
    # `ctx.invoked_subcommand` is set).
    if ctx.invoked_subcommand is None:
        console.print(
            Panel(
                "[bold cyan]Deep introspection of ML model artifacts[/bold cyan]\n"
                "[dim](.pt, .safetensors, .gguf) for malware, license risk, and silent drift.[/dim]\n\n"
                "[bold]Try it now:[/bold]\n\n"
                "    [white]$ aisbom scan hf://google-bert/bert-base-uncased[/white]\n\n"
                "[dim]Run [white]aisbom --help[/white] for the full command reference.[/dim]",
                title=" AIsbom ",
                border_style="cyan",
                padding=(1, 2),
                expand=False,
            )
        )
        raise typer.Exit(code=0)


# Thread-safe storage for update checks
update_result = {"version": None}

def run_version_check_wrapper():
    """Wrapper to run version check and store result."""
    update_result["version"] = check_latest_version()

def _check_update_status():
    """Checks if update thread finished and prints message if needed."""
    # We join with a tiny timeout to see if it's done without blocking
    # Since we call this at the END of the command, the network request likely finished.
    # If it's still hung, we skip showing the message to avoid delay.
    # Note: Threads in Python are daemon by default? No, we need to set daemon=True
    # so it doesn't block exit if network hangs. But here we just want to check results.
    if update_result["version"]:
        ver = update_result["version"]
        try:
             curr = importlib.metadata.version("aisbom-cli")
        except:
             curr = "unknown"
             
        console.print(Panel(
            f"💡 [bold yellow]Update Available:[/bold yellow] You are on v{curr}. v{ver} is available.\n"
            f"Run [bold white]pip install --upgrade aisbom-cli[/bold white] to update.",
            border_style="yellow",
            expand=False
        ))


def _classify_target(target: str) -> str:
    """Bucket the scan target into a category label for telemetry."""
    if target.startswith("hf://"):
        return "huggingface"
    if target.startswith("https://"):
        return "https"
    if target.startswith("http://"):
        return "http"
    return "local"


def _classify_http_status(exc: BaseException) -> str:
    """Bucket a fetch exception into a low-cardinality status label.

    Returns the numeric HTTP status as a string for an HTTPError (e.g. "401",
    "404"), "timeout" / "connection_error" for the corresponding network
    failures, or "other" for anything else. Never includes a response body or
    any URL — only the diagnostic bucket. Timeout is checked before
    ConnectionError so a ConnectTimeout (a subclass of both) buckets as a
    timeout.
    """
    if isinstance(exc, requests.exceptions.HTTPError):
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
        if status is not None:
            return str(status)
        return "other"
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection_error"
    return "other"


def _token_present() -> str:
    """Report whether an HF token env var is set, as "true"/"false".

    Only presence is reported — the token value is never read into telemetry.
    """
    has_token = bool(os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN"))
    return "true" if has_token else "false"


def _scan_error_payload(exc: BaseException, target: str) -> dict:
    """Build the `cli_error` telemetry payload for a scan-path failure.

    Single source of truth for the event shape (parent #55) so every emit
    site — the top-level `except` and the per-target fetch-failure path —
    sends exactly the same low-cardinality keys and never a URL, repo id,
    hostname, or response body.
    """
    return {
        "command": "scan",
        "error_type": type(exc).__name__,
        "http_status": _classify_http_status(exc),
        "token_present": _token_present(),
        "target_type": _classify_target(target),
    }


def _maybe_print_loop_warning(count: int, http_status: str) -> None:
    """Stale-loop nudge (#99): warn once the same failure repeats N runs.

    Printed to stderr only, after the per-file error messages, so CI log
    parsers and `--output` consumers are unaffected. The upgrade line rides
    on the background version check that scan already started — when that
    thread hasn't reported a newer version, the line is simply omitted (no
    extra network call, no blocking).
    """
    if count < loop_state.LOOP_WARN_THRESHOLD:
        return
    # Wording note: the fingerprint is target-blind by design (no URLs/repo
    # ids on disk), so consecutive failures on *different* models with the
    # same error shape share one counter — say "your scans", not "this scan".
    lines = [
        f"[bold yellow]⚠ Your scans have hit the same error "
        f"{count} times in a row.[/bold yellow]"
    ]
    if http_status in ("401", "403"):
        if _token_present() == "true":
            lines.append(
                "• A token is set but authentication keeps failing — verify "
                "HF_TOKEN is valid and the model's license is accepted "
                '(see README "Authentication").'
            )
        else:
            lines.append(
                "• If this is a gated/private Hugging Face repo: set HF_TOKEN "
                '(see README "Authentication").'
            )
    newer = update_result.get("version")
    if newer:
        try:
            curr = importlib.metadata.version("aisbom-cli")
        except Exception:
            curr = "unknown"
        lines.append(
            f"• You are on v{curr}; v{newer} includes fixes for repeated "
            "fetch failures — run: pip install --upgrade aisbom-cli"
        )
    err_console.print(
        Panel("\n".join(lines), border_style="yellow", expand=False)
    )


def _format_fetch_error(exc: BaseException, url: str) -> str:
    """Status-aware, traceback-free message for a fetch failure.

    Reactive (parent #55, #58): we make the request, then adapt the wording to
    the *observed* status — the message never claims a cause it can't see. Auth
    branches additionally split on whether a token was present, so a gated repo
    with no token and a bad/insufficient token get different remediation.
    """
    status = _classify_http_status(exc)
    if url.startswith("hf://"):
        # Resolve-time failure: the raw target is a repo id, not a byte URL.
        host = "huggingface.co"
        name = url[len("hf://"):] or url
    else:
        host = urlparse(url).hostname or "the remote host"
        name = Path(urlparse(url).path).name or url

    if status in ("401", "403"):
        if _token_present() == "true":
            return (
                f"Authentication failed for {name} despite a token being set. "
                "Verify HF_TOKEN is valid and has read access — you may need to "
                "accept the model's license on huggingface.co."
            )
        return (
            f"Authentication failed for {name}; the model appears to be private "
            "or gated. Set HF_TOKEN with a token that has read access."
        )
    if status in ("timeout", "connection_error"):
        return (
            f"Network error reaching {host}. In CI, check that egress/firewall "
            "allows HTTPS to huggingface.co and its LFS CDN."
        )
    if status == "404":
        return f"{name} not found (HTTP 404); check the repo id / URL."
    if status.isdigit():
        return f"Failed to fetch {name} (HTTP {status})."
    return f"Failed to fetch {name}."


def _summarize_model_format(artifacts: list[dict]) -> str:
    """Reduce per-artifact `framework` values to a single label.

    Returns 'none' if no artifacts, the framework name if all match,
    or 'mixed' if multiple distinct frameworks were found."""
    if not artifacts:
        return "none"
    formats = {(a.get("framework") or "unknown").lower() for a in artifacts}
    if len(formats) == 1:
        return formats.pop()
    return "mixed"


def _maybe_emit_install_event() -> threading.Thread | None:
    """Fire cli_install_first_seen on the very first invocation per machine.

    Suppressed in CI (config dirs are ephemeral there) and when the home
    config dir isn't writable. Self-gates via the existence of
    ~/.aisbom/config.json — once that file is created, this is a no-op."""
    if telemetry.is_ci():
        return None
    home = telemetry.get_config_dir()
    if home is None:
        return None
    if (home / "config.json").exists():
        return None
    # post_event() will internally call get_or_init_config() which writes
    # config.json, so the next invocation sees it and skips this branch.
    return telemetry.post_event("cli_install_first_seen", {})


def _flush_telemetry_threads(threads: list[threading.Thread | None]) -> None:
    """Wait briefly for in-flight telemetry POSTs to flush before exit."""
    for t in threads:
        if t is not None:
            t.join(timeout=2.0)


def _attribution_ref(base_url: str) -> str:
    """Append `ref=cli` to a URL so we can attribute return visits to CLI
    users in GA4 Acquisition reports. Strips the tag when the user has opted
    out of telemetry — the URL stays useful, just untracked."""
    if os.getenv("AISBOM_NO_TELEMETRY"):
        return base_url
    sep = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}ref=cli"


def _render_scan_footer(
    *,
    share_url: str | None,
    output_path: str | None,
    output_format: "OutputFormat",
    share_attempted: bool,
) -> None:
    """Print the post-scan acquisition footer (Phase 4.3).

    Drives recurring engagement with aisbom.io properties — the viewer
    (per-scan) and the advisories page (weekly). Three flavors:

    1. `--share` succeeded → point at the hosted viewer URL.
    2. `--share` not used (or failed) and machine-readable format → drag-and-
       drop hint + a nudge to try `--share` next time.
    3. Markdown format → only the advisories link (no viewer hint, since
       the markdown report isn't a viewer input).

    URL attribution respects `AISBOM_NO_TELEMETRY` via `_attribution_ref`.
    """
    lines: list[str] = []

    if share_url:
        lines.append(
            f"🔗 [bold]View this SBOM online:[/bold] "
            f"[underline cyan]{_attribution_ref(share_url)}[/underline cyan]"
        )
    elif output_format in (OutputFormat.JSON, OutputFormat.SPDX) and output_path:
        lines.append(
            f"📊 [bold]Drag [cyan]{output_path}[/cyan] into the offline viewer:[/bold]\n"
            f"   [underline cyan]{_attribution_ref('https://aisbom.io/viewer')}[/underline cyan]"
        )
        if not share_attempted:
            lines.append(
                "💡 [dim]Tip: re-run with [white]--share[/white] to get a hosted viewer link.[/dim]"
            )

    # Always: advisories. Recurring re-engagement vector independent of format.
    lines.append(
        f"📰 [bold]Latest model advisories:[/bold] "
        f"[underline cyan]{_attribution_ref('https://aisbom.io/advisories')}[/underline cyan]"
    )

    console.print(
        Panel(
            "\n".join(lines),
            title=" Next steps ",
            border_style="blue",
            expand=False,
        )
    )


class OutputFormat(str, Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    SPDX = "spdx"

def _generate_markdown(results: dict) -> str:
    """Render a GitHub-flavored Markdown report for CI artifacts."""
    lines = []
    deps_count = len(results.get("dependencies", []))
    lines.append("## AIsbom Report")
    lines.append("")
    lines.append(f"- Dependencies found: **{deps_count}**")
    lines.append("")
    lines.append("| Filename | Framework | Security Risk | Legal Risk | SHA256 Hash |")
    lines.append("| :--- | :--- | :--- | :--- | :--- |")

    for art in results.get("artifacts", []):
        risk = art.get("risk_level", "UNKNOWN")
        legal = art.get("legal_status", "UNKNOWN")
        risk_upper = risk.upper()
        legal_upper = legal.upper()

        if "CRITICAL" in risk_upper or "HIGH" in risk_upper:
            risk_icon = "🔴"
        elif "MEDIUM" in risk_upper:
            risk_icon = "🟡"
        else:
            risk_icon = "🟢"

        legal_icon = "🔴" if "RISK" in legal_upper else "🟢"
        hash_short = (art.get("hash") or "")[:8] or "N/A"

        lines.append(
            f"| {art.get('name', '?')} | {art.get('framework', '?')} | {risk_icon} {risk} | {legal_icon} {legal} | {hash_short} |"
        )

    return "\n".join(lines)

@app.command()
def scan(
    target: str = typer.Argument(
        ".",
        help=(
            "Local directory, HTTP(S) URL, or Hugging Face slug "
            "(e.g. ./models, https://example.com/model.pt, hf://google-bert/bert-base-uncased)."
        ),
    ),
    output: str | None = typer.Option(None, help="Output file path"),
    schema_version: str = typer.Option("1.6", help="CycloneDX schema version (default is 1.6)", case_sensitive=False, rich_help_panel="Advanced Options"),
    spdx_version: str = typer.Option("2.3", help="SPDX version (2.3 or 3.0)", case_sensitive=False, rich_help_panel="Advanced Options"),
    fail_on_risk: bool = typer.Option(True, help="Return exit code 2 if Critical risks are found"),
    strict: bool = typer.Option(False, help="Enable strict allowlisting mode (flags any unknown imports)"),
    lint: bool = typer.Option(False, help="Enable Migration Linter (checks for weights_only=True compatibility)"),
    format: OutputFormat = typer.Option(OutputFormat.JSON, help="Output format (JSON for SBOM, MARKDOWN for Human Report, SPDX for Compliance)"),
    share: bool = typer.Option(
        False,
        help=(
            "Upload the generated SBOM to aisbom.io and print a public viewer URL. "
            "Anyone with the link can view the SBOM; data expires after 30 days. "
            "Prompts for confirmation before uploading unless --share-yes is also set."
        ),
    ),
    share_yes: bool = typer.Option(
        False,
        "--share-yes",
        help=(
            "Skip the --share confirmation prompt. Intended for CI/CD pipelines; "
            "do not pass this flag interactively unless you understand that the "
            "uploaded SBOM becomes publicly viewable for 30 days."
        ),
    ),
):
    """
    Deep Introspection Scan: Analyzes binary headers and dependency manifests.
    """
    # Start background check
    t = threading.Thread(target=run_version_check_wrapper, daemon=True)
    t.start()

    console.print(Panel.fit(f"🚀 [bold cyan]AIsbom[/bold cyan] Scanning: [underline]{target}[/underline]"))

    # Telemetry: per-invocation scan_id groups all events from this scan into
    # one GA4 session. Started here so an early failure still has an id.
    scan_id = uuid.uuid4().hex
    t_start = time.monotonic()
    telemetry_threads: list[threading.Thread | None] = [
        _maybe_emit_install_event(),
    ]

    # Phase 4.3 — captured by the --share success path below and read by the
    # acquisition footer at scan end. Function-scope name so the inner JSON
    # branch can write to it and the footer can read it.
    share_url: str | None = None

    # 1. Run the Logic
    try:
        scanner = DeepScanner(target, strict_mode=strict, lint=lint)
        if isinstance(target, str) and (target.startswith("http://") or target.startswith("https://") or target.startswith("hf://")):
            with console.status("[cyan]Resolving remote repository...[/cyan]"):
                results = scanner.scan()
        else:
            results = scanner.scan()
    except Exception as e:
        # Safety net for unexpected scan crashes. Per-target *fetch* failures are
        # caught inside the scanner now (recorded as structured errors, no
        # traceback); anything reaching here is genuinely unexpected. Crashes
        # still feed the loop detector (#99) — a repeating crash is a loop too.
        payload = _scan_error_payload(e, target)
        crash_count = loop_state.record_failure(
            payload["error_type"], payload["http_status"], payload["target_type"]
        )
        payload["consecutive_failures"] = loop_state.bucket_count(crash_count)
        _maybe_print_loop_warning(crash_count, payload["http_status"])
        err_thread = telemetry.post_event(
            "cli_error",
            payload,
            scan_id=scan_id,
        )
        _flush_telemetry_threads(telemetry_threads + [err_thread])
        raise
    # Track highest risk for exit code purposes (CI friendly)
    def _risk_score(label: str) -> int:
        text = (label or "").upper()
        if "CRITICAL" in text:
            return 3
        if "MEDIUM" in text:
            return 2
        if "LOW" in text:
            return 1
        return 0

    highest_risk = max((_risk_score(a.get("risk_level")) for a in results['artifacts']), default=0)
    exit_code = 0
    if results['errors']:
        exit_code = max(exit_code, 1)
    if fail_on_risk and highest_risk >= 3:
        exit_code = 2

    # Reactive fetch-failure handling (#58). The scanner caught these per-target
    # and kept going, so other targets still rendered above. For each one, print
    # a clean status-aware message to stderr (no traceback) and emit a cli_error
    # carrying the same diagnostic buckets as the top-level except — so a single
    # failed scan emits both a cli_error (the failure) and the normal cli_scan
    # (context) below. Intentional; see the slice notes.
    fetch_failures = [e for e in results['errors'] if e.get('fetch_failure')]
    # Loop detection (#99) works at scan granularity ("N runs in a row"): the
    # first fetch failure's fingerprint represents the invocation. A scan with
    # no fetch failures breaks any recorded loop for this target class.
    if fetch_failures:
        first_payload = _scan_error_payload(fetch_failures[0].get('exception'), target)
        loop_count = loop_state.record_failure(
            first_payload["error_type"],
            first_payload["http_status"],
            first_payload["target_type"],
        )
    else:
        loop_state.record_success(_classify_target(target))
        loop_count = 0
    # Sharded models fail one-per-shard with near-identical messages (12
    # shards → 12 lines differing only in filename). Group by status bucket
    # and print each distinct failure mode once, naming the first file and
    # counting the rest. Telemetry below stays per-file (#58 semantics).
    failures_by_status: dict[str, list[dict]] = {}
    for err in fetch_failures:
        status = _classify_http_status(err.get('exception'))
        failures_by_status.setdefault(status, []).append(err)
    for group in failures_by_status.values():
        first = group[0]
        msg = _format_fetch_error(first.get('exception'), first.get('file', ''))
        if len(group) > 1:
            plural = "file" if len(group) == 2 else "files"
            msg += f" [dim](+{len(group) - 1} more {plural} with the same error)[/dim]"
        err_console.print(f"[bold red]✖[/bold red] {msg}")
    for err in fetch_failures:
        payload = _scan_error_payload(err.get('exception'), target)
        payload["consecutive_failures"] = loop_state.bucket_count(loop_count)
        telemetry_threads.append(
            telemetry.post_event("cli_error", payload, scan_id=scan_id)
        )
    if fetch_failures:
        _maybe_print_loop_warning(loop_count, first_payload["http_status"])

    # Telemetry: fire cli_scan plus any conditional follow-ups now that the
    # scan completed and risk is known. Non-blocking; flushed before exit.
    _risk_label = {3: "critical", 2: "medium", 1: "low", 0: "none"}.get(highest_risk, "unknown")
    scan_duration_ms = int((time.monotonic() - t_start) * 1000)
    scan_params = {
        "target_type": _classify_target(target),
        "model_format": _summarize_model_format(results.get("artifacts", [])),
        "risk_level_max": _risk_label,
        "scan_duration_ms": str(scan_duration_ms),
        "file_count": str(len(results.get("artifacts", []))),
        "parse_error_count": str(len(results.get("errors", []))),
        "strict_mode": "true" if strict else "false",
    }
    telemetry_threads.append(
        telemetry.post_event("cli_scan", scan_params, scan_id=scan_id)
    )
    if highest_risk >= 3:
        critical_count = sum(
            1 for a in results.get("artifacts", [])
            if "CRITICAL" in (a.get("risk_level") or "").upper()
        )
        telemetry_threads.append(
            telemetry.post_event(
                "cli_scan_critical_found",
                {"critical_count": str(critical_count)},
                scan_id=scan_id,
            )
        )
    if strict:
        telemetry_threads.append(
            telemetry.post_event("cli_strict_mode", {}, scan_id=scan_id)
        )

    # 2. Render Results (UI)
    if results['artifacts']:
        table = Table(title="🧠 AI Model Artifacts Found")
        table.add_column("Filename", style="cyan")
        table.add_column("Framework", style="magenta")
        table.add_column("Security Risk", style="bold red")
        table.add_column("Legal Risk", style="yellow")
        table.add_column("Metadata", style="dim")
        
        for art in results['artifacts']:
            risk_style = "green" if "LOW" in art['risk_level'] else "red"
            legal_style = "red" if "RISK" in art['legal_status'] else "green"
            # Add Hash to table output to prove it works visually
            display_meta = f"SHA256: {art.get('hash', 'N/A')[:8]}... | " + str(art.get('details', ''))[:20]
            table.add_row(
                art['name'], 
                art['framework'], 
                f"[{risk_style}]{art['risk_level']}[/{risk_style}]",
                f"[{legal_style}]{art['legal_status']}[/{legal_style}]",
                display_meta
            )
        console.print(table)
    else:
        console.print("[yellow]No AI models found.[/yellow]")

    # LINT OUTPUT (Migration Report)
    lint_failures = [a for a in results['artifacts'] if a.get('details', {}).get('lint_report')]
    if lint_failures:
        console.print("\n[bold white]🛡️  Migration Readiness (weights_only=True)[/bold white]")
        lint_table = Table(show_header=True, header_style="bold magenta")
        lint_table.add_column("File", style="cyan")
        lint_table.add_column("Issue", style="red")
        lint_table.add_column("Recommendation", style="yellow")
        
        for art in lint_failures:
            report = art['details']['lint_report']
            for issue in report:
                lint_table.add_row(
                    art['name'],
                    issue['msg'],
                    issue['hint']
                )
        console.print(lint_table)
        console.print("[dim]Use --no-lint to disable this check.[/dim]\n")


    if results['dependencies']:
        console.print(f"\n📦 Found [bold]{len(results['dependencies'])}[/bold] Python libraries.")

    # Parse errors only — fetch failures already printed their status-aware
    # message to stderr above and don't fit the "Could not parse" framing.
    parse_errors = [e for e in results['errors'] if not e.get('fetch_failure')]
    if parse_errors:
        console.print("\n[bold red]⚠️ Errors Encountered:[/bold red]")
        for err in parse_errors:
            console.print(f"  - Could not parse [yellow]{err['file']}[/yellow]: {err['error']}")
    
    # 3. Generate CycloneDX SBOM (Standard Compliance)
    bom = Bom()
    lf = LicenseFactory()
    
    # Add Models
    for art in results['artifacts']:
        c = Component(
            name=art['name'],
            type=ComponentType.MACHINE_LEARNING_MODEL,
            description=f"Risk: {art['risk_level']} | Framework: {art['framework']} | Legal: {art['legal_status']} | License: {art.get('license')}"
        )
        # Add SHA256 Hash if available
        if 'hash' in art and art['hash'] != 'hash_error':
            c.hashes.add(HashType(
                alg=HashAlgorithm.SHA_256,
                content=art['hash']
            ))
        # Add License info to SBOM if known
        if art.get('license') and art['license'] != 'Unknown':
            # Create a License object (using name since we don't have SPDX ID validation yet)
            lic = lf.make_from_string(art['license'])
            c.licenses.add(lic)

        # Attach structured, namespaced per-format findings as CycloneDX
        # properties so consumers can render them directly (the description
        # string above is kept unchanged for backwards compatibility).
        for prop_name, prop_value in build_component_properties(art):
            c.properties.add(Property(name=prop_name, value=prop_value))

        bom.components.add(c)

    # Add Libraries
    for dep in results['dependencies']:
        c = Component(
            name=dep['name'],
            version=dep['version'],
            type=ComponentType.LIBRARY
        )
        bom.components.add(c)

    # 4. Save to Disk
    if output is None:
        if format == OutputFormat.JSON:
             output = "sbom.json"
        elif format == OutputFormat.SPDX:
             output = "sbom.spdx.json"
        else:
             output = "aisbom-report.md"

    if format == OutputFormat.JSON:
        if schema_version == "1.5":
            outputter = JsonV1Dot5(bom)
        else:
            outputter = JsonV1Dot6(bom)
            
        with open(output, "w") as f:
            f.write(outputter.output_as_string())
        
        console.print(f"\n[bold green]✔ Compliance Artifact Generated:[/bold green] {output} (CycloneDX v{schema_version})")

        has_content = bool(results.get('artifacts') or results.get('dependencies'))
        if share and has_content:
            do_share = True
            if not share_yes:
                do_share = typer.confirm(
                    "Upload this SBOM to aisbom.io to generate a shareable link?\n"
                    "Data will be public to anyone with the link and expires in 30 days.", 
                    default=False
                )
                if not do_share:
                    console.print("[dim]Share cancelled.[/dim]")

            if do_share:
                with console.status("[cyan]Uploading SBOM to aisbom.io...[/cyan]"):
                    try:
                        json_str = outputter.output_as_string()
                        res = requests.post(
                            "https://aisbom.io/api/sbom-share",
                            data=json_str,
                            headers={
                                "Content-Type": "application/json",
                                "User-Agent": telemetry._build_user_agent()
                            },
                            timeout=15.0
                        )
                        res.raise_for_status()
                        share_url = res.json().get("url")
                        
                        console.print(f"\n[bold green]✔ Share Link Created:[/bold green] [underline cyan]{share_url}[/underline cyan]")
                        console.print("[dim]Anyone with this link can view this SBOM. Expires in 30 days.[/dim]")
                        
                        telemetry_threads.append(telemetry.post_event(
                            "cli_share_created",
                            {"has_share_yes": "true" if share_yes else "false"},
                            scan_id=scan_id
                        ))
                    except Exception as e:
                        console.print(f"\n[bold red]✖ Failed to create share link:[/bold red] {e}")

    elif format == OutputFormat.SPDX:
        from .spdx_gen import generate_spdx_sbom
        spdx_json = generate_spdx_sbom(results)
        with open(output, "w") as f:
            f.write(spdx_json)
        console.print(f"\n[bold green]✔ Compliance Artifact Generated:[/bold green] {output} (SPDX v2.3)")
    else:
        markdown = _generate_markdown(results)
        with open(output, "w") as f:
            f.write(markdown)
        console.print(f"\n[bold green]✔ Markdown Report Generated:[/bold green] {output}")

    # Phase 4.3 — acquisition footer (replaces the previous "Visualize this
    # report" panel). Always shown after a successful scan. Drives recurring
    # engagement with aisbom.io's viewer + advisories pages.
    _render_scan_footer(
        share_url=share_url,
        output_path=output,
        output_format=format,
        share_attempted=share,
    )

    # Signal exit behavior to the user
    if exit_code == 2:
        console.print("[bold red]CRITICAL risks detected.[/bold red] Exiting with code 2 (controlled by --fail-on-risk).")
    elif exit_code == 1:
        console.print("[bold yellow]Errors encountered during scan.[/bold yellow] Exiting with code 1.")

    # Check update status before exiting
    _check_update_status()

    # Flush in-flight telemetry POSTs so events aren't lost on exit.
    _flush_telemetry_threads(telemetry_threads)

    # Non-zero exit codes for CI/CD when high risk or errors are present
    raise typer.Exit(code=exit_code)

@app.command()
def info():
    """
    Display current version and environment info.
    """
    try:
        # CRITICAL FIX: Use "aisbom-cli" (the PyPI package name), not "aisbom" (the folder)
        ver = importlib.metadata.version("aisbom-cli")
    except importlib.metadata.PackageNotFoundError:
        ver = "unknown (dev build)"

    # Phase 4 help-pass: surface telemetry state in `info` so users have one
    # canonical place to confirm whether events are firing on their machine.
    telemetry_state = (
        "opted out via AISBOM_NO_TELEMETRY"
        if os.getenv("AISBOM_NO_TELEMETRY")
        else "enabled (set AISBOM_NO_TELEMETRY=1 to disable)"
    )

    console.print(Panel(
        f"[bold cyan]AI SBOM[/bold cyan]: AI Software Bill of Materials - The Supply Chain for Artificial Intelligence\n"
        f"[bold]Version:[/bold] {ver}\n"
        f"[bold]License:[/bold] Apache 2.0\n"
        f"[bold]Website:[/bold] https://www.aisbom.io\n"
        f"[bold]Repository:[/bold] https://github.com/Lab700xOrg/aisbom\n"
        f"[bold]Telemetry:[/bold] {telemetry_state}",
        title=" System Info ",
        border_style="magenta",
        expand=False
    ))

@app.command()
def generate_test_artifacts(
    directory: str = typer.Argument(".", help="Directory to generate test files in")
):
    """
    Generates harmless 'mock' artifacts (Malware simulator & License risk) for testing.
    """
    target_path = Path(directory)
    if not target_path.exists():
        target_path.mkdir(parents=True)

    # FIX: Use relative path to hide your username/home folder
    # If it's the current dir, just show "."
    display_path = "." if directory == "." else directory

    console.print(Panel.fit(f"[bold blue]🧪 Generating Test Artifacts in:[/bold blue] {display_path}"))
    
    # 1. Create Mock Malware
    mock_malware_path = create_mock_malware_file(target_path)
    console.print(f"  [red]• Created:[/red] {mock_malware_path.name} (Simulates Pickle RCE)")
    
    # 2. Create Mock Legal Risk
    mock_legal_path = create_mock_restricted_file(target_path)
    console.print(f"  [yellow]• Created:[/yellow] {mock_legal_path.name} (Simulates Restrictive License)")
    
    # 3. Create GGUF Risk (New)
    mock_gguf_path = create_mock_gguf(target_path)
    console.print(f"  [yellow]• Created:[/yellow] {mock_gguf_path.name} (Simulates GGUF License Risk)")

    # 4. Create Diff Testing Data (New)
    try:
        demo_old, demo_new = create_demo_diff_sboms(target_path)
        console.print(f"  [cyan]• Created:[/cyan] demo_data/ (Baseline & Drifted SBOMs for 'diff' testing)")
    except Exception as e:
        console.print(f"  [red]• Error creating diff demos:[/red] {e}")

    # 5. Create Broken Migration (The new Linter use case)
    broken_path = create_mock_broken_file(target_path)
    console.print(f"  [magenta]• Created:[/magenta] {broken_path.name} (Safe, but fails weights_only=True)")
    
    console.print("\n[bold green]Done.[/bold green] Now run: [code]aisbom scan .[/code]")


@app.command()
def diff(
    old_file: str = typer.Argument(..., help="Path to baseline SBOM (JSON)"),
    new_file: str = typer.Argument(..., help="Path to new SBOM (JSON)"),
    fail_on_risk_increase: bool = typer.Option(True, help="Exit with code 1 if risk increases or hashes drift")
):
    """
    Compare two SBOM files (CycloneDX JSON) and detect drift in risks, licenses, dependencies, or model hashes.
    """
    # Start background check
    t = threading.Thread(target=run_version_check_wrapper, daemon=True)
    t.start()

    # Telemetry: per-invocation scan_id groups events into one GA4 session.
    scan_id = uuid.uuid4().hex
    telemetry_threads: list[threading.Thread | None] = [
        _maybe_emit_install_event(),
    ]

    path_old = Path(old_file)
    path_new = Path(new_file)

    if not path_old.exists() or not path_new.exists():
        console.print("[bold red]Error:[/bold red] One or both files do not exist.")
        _flush_telemetry_threads(telemetry_threads)
        raise typer.Exit(code=1)

    try:
        differ = SBOMDiff(path_old, path_new)
        result = differ.compare()
    except Exception as e:
        console.print(f"[bold red]Error parsing SBOMs:[/bold red] {e}")
        telemetry_threads.append(telemetry.post_event(
            "cli_error",
            {"command": "diff", "error_type": type(e).__name__},
            scan_id=scan_id,
        ))
        _flush_telemetry_threads(telemetry_threads)
        raise typer.Exit(code=1)

    # Telemetry: comparison succeeded; fire cli_diff with drift signal.
    has_drift = bool(result.added or result.removed or result.changed)
    telemetry_threads.append(telemetry.post_event(
        "cli_diff",
        {"has_drift": "true" if has_drift else "false"},
        scan_id=scan_id,
    ))

    console.print(Panel.fit(f"[bold cyan]Comparing[/bold cyan] {path_old.name} -> {path_new.name}"))

    table = Table(title="Drift Analysis")
    table.add_column("Component", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Change", style="yellow")
    table.add_column("Security Risk", style="bold red")
    table.add_column("Legal Risk", style="yellow")
    table.add_column("Details", style="white")

    # Added
    for item in result.added:
        risk = differ._get_risk(item)
        lic = differ._get_license(item)
        legal_stat = differ._get_legal_status(item)
        
        sec_style = "bold red" if risk == "CRITICAL" else "green"
        legal_style = "bold red" if legal_stat == "LEGAL RISK" else "green"
        
        table.add_row(item['name'], "Added", "NEW", f"[{sec_style}]{risk}[/{sec_style}]", f"[{legal_style}]{legal_stat}[/{legal_style}]", f"Lic: {lic}")

    # Removed
    for item in result.removed:
        table.add_row(item['name'], "Removed", "DELETED", "-", "-", "")

    # Changed
    for change in result.changed:
        details = []
        sec_risk_disp = "-"
        legal_risk_disp = "-"
        
        if change.risk_diff:
            old_r, new_r = change.risk_diff
            style = "bold red" if new_r == "CRITICAL" else "yellow"
            sec_risk_disp = f"{old_r} -> [{style}]{new_r}[/{style}]"
        
        if change.legal_status_diff:
            old_s, new_s = change.legal_status_diff
            style = "bold red" if new_s == "LEGAL RISK" else "green"
            legal_risk_disp = f"{old_s} -> [{style}]{new_s}[/{style}]"
        
        # If license text changed but status didn't, still allow DETAILS to show the text change
        # But ensure 'Legal Risk' column reflects current status if not drifted
        if not change.legal_status_diff and change.license_diff:
             # Just show current status
             # We need to re-fetch current status to show it, or leave it blank/dash if not drifted?
             # User implies they want to assess risk. If it's a diff, we usually show what changed.
             # If status is stuck at "LEGAL RISK" -> "LEGAL RISK" but license changed, we should probably show that?
             # For now, if no status diff, we leave it as "-" to indicate STABLE risk level, but details show the change.
             pass

        if change.license_diff:
            old_l, new_l = change.license_diff
            details.append(f"Lic: {old_l} -> {new_l}")
            
        if change.version_diff:
            old_v, new_v = change.version_diff
            details.append(f"Ver: {old_v} -> {new_v}")
            
        if change.hash_diff:
            old_h, new_h = change.hash_diff
            details.append(f"Hash: {old_h[:8]}... -> [red]{new_h[:8]}...[/red]")
            # If hash drifted, this is an Integrity Failure regardless of scanner score
            if sec_risk_disp == "-":
                sec_risk_disp = "[bold red]INTEGRITY FAIL[/bold red]"
            else:
                # If risk ALSO increased, append it
                sec_risk_disp += "\n[bold red]INTEGRITY FAIL[/bold red]"
        
        table.add_row(change.name, "Modified", "DRIFT", sec_risk_disp, legal_risk_disp, ", ".join(details))

    if result.added or result.removed or result.changed:
        console.print(table)
    else:
        console.print("[green]No changes detected.[/green]")

    if fail_on_risk_increase and (result.risk_increased or result.hash_drifted):
        console.print("\n[bold red]FAILURE: Critical risk increase or hash drift detected![/bold red]")
        _flush_telemetry_threads(telemetry_threads)
        raise typer.Exit(code=1)

    console.print("\n[bold green]Success: No critical regression detected.[/bold green]")

    _check_update_status()
    _flush_telemetry_threads(telemetry_threads)

if __name__ == "__main__":
    app()
