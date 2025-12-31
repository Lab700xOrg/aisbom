import typer
import json
import tomllib
import importlib.metadata
from enum import Enum
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.output.json import JsonV1Dot5, JsonV1Dot6
from cyclonedx.factory.license import LicenseFactory
from .mock_generator import create_mock_malware_file, create_mock_restricted_file, create_mock_gguf, create_demo_diff_sboms
from pathlib import Path
import importlib.metadata
from .scanner import DeepScanner
from .diff import SBOMDiff

app = typer.Typer()
console = Console()

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
    target: str = typer.Argument(".", help="Directory or URL (http/hf://) to scan"),
    output: str | None = typer.Option(None, help="Output file path"),
    schema_version: str = typer.Option("1.6", help="CycloneDX schema version (default is 1.6)", case_sensitive=False, rich_help_panel="Advanced Options"),
    spdx_version: str = typer.Option("2.3", help="SPDX version (2.3 or 3.0)", case_sensitive=False, rich_help_panel="Advanced Options"),
    fail_on_risk: bool = typer.Option(True, help="Return exit code 2 if Critical risks are found"),
    strict: bool = typer.Option(False, help="Enable strict allowlisting mode (flags any unknown imports)"),
    format: OutputFormat = typer.Option(OutputFormat.JSON, help="Output format (JSON for SBOM, MARKDOWN for Human Report, SPDX for Compliance)")
):
    """
    Deep Introspection Scan: Analyzes binary headers and dependency manifests.
    """
    console.print(Panel.fit(f"🚀 [bold cyan]AIsbom[/bold cyan] Scanning: [underline]{target}[/underline]"))

    # 1. Run the Logic
    scanner = DeepScanner(target, strict_mode=strict)
    if isinstance(target, str) and (target.startswith("http://") or target.startswith("https://") or target.startswith("hf://")):
        with console.status("[cyan]Resolving remote repository...[/cyan]"):
            results = scanner.scan()
    else:
        results = scanner.scan()
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

    if results['dependencies']:
        console.print(f"\n📦 Found [bold]{len(results['dependencies'])}[/bold] Python libraries.")

    if results['errors']:
        console.print("\n[bold red]⚠️ Errors Encountered:[/bold red]")
        for err in results['errors']:
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

    # Show visualization panel for machine-readable formats
    if format in [OutputFormat.JSON, OutputFormat.SPDX]:
        try:
            ver = importlib.metadata.version("aisbom-cli")
        except importlib.metadata.PackageNotFoundError:
            ver = "unknown"

        viewer_url = f"https://www.aisbom.io/viewer.html?utm_source=cli&utm_medium=terminal&utm_campaign=scan_output&utm_version={ver}"

        console.print(Panel(
            f"[bold white]📊 Visualize this report:[/bold white]\n"
            f"Drag and drop [cyan]{output}[/cyan] into our secure offline viewer:\n"
            f"👉 [link={viewer_url}]Open Secure Viewer (aisbom.io)[/link]",
            border_style="blue",
            expand=False
        ))

    # Signal exit behavior to the user
    if exit_code == 2:
        console.print("[bold red]CRITICAL risks detected.[/bold red] Exiting with code 2 (controlled by --fail-on-risk).")
    elif exit_code == 1:
        console.print("[bold yellow]Errors encountered during scan.[/bold yellow] Exiting with code 1.")

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

    console.print(Panel(
        f"[bold cyan]AI SBOM[/bold cyan]: AI Software Bill of Materials - The Supply Chain for Artificial Intelligence\n"
        f"[bold]Version:[/bold] {ver}\n"
        f"[bold]License:[/bold] Apache 2.0\n"
        f"[bold]Website:[/bold] https://www.aisbom.io\n"
        f"[bold]Repository:[/bold] https://github.com/Lab700xOrg/aisbom",
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
    path_old = Path(old_file)
    path_new = Path(new_file)

    if not path_old.exists() or not path_new.exists():
        console.print("[bold red]Error:[/bold red] One or both files do not exist.")
        raise typer.Exit(code=1)

    try:
        differ = SBOMDiff(path_old, path_new)
        result = differ.compare()
    except Exception as e:
        console.print(f"[bold red]Error parsing SBOMs:[/bold red] {e}")
        raise typer.Exit(code=1)

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
        raise typer.Exit(code=1)
    
    console.print("\n[bold green]Success: No critical regression detected.[/bold green]")

if __name__ == "__main__":
    app()
