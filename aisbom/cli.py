import typer
import json
import tomllib
import importlib.metadata
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.output.json import JsonV1Dot5, JsonV1Dot6
from cyclonedx.factory.license import LicenseFactory
from .generator import create_mock_malware_file, create_mock_restricted_file
from pathlib import Path

# Import our new logic engine
from .scanner import DeepScanner

app = typer.Typer()
console = Console()

@app.command()
def scan(
    directory: str = typer.Argument(".", help="Target directory to scan"),
    output: str = typer.Option("sbom.json", help="Output file path"),
    schema_version: str = typer.Option("1.6", help="CycloneDX schema version (default is 1.6)", case_sensitive=False, rich_help_panel="Advanced Options")
):
    """
    Deep Introspection Scan: Analyzes binary headers and dependency manifests.
    """
    console.print(Panel.fit(f"🚀 [bold cyan]AIsbom[/bold cyan] Scanning: [underline]{directory}[/underline]"))

    # 1. Run the Logic
    scanner = DeepScanner(directory)
    results = scanner.scan()
    
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
    if schema_version == "1.5":
        outputter = JsonV1Dot5(bom)
    else:
        outputter = JsonV1Dot6(bom)
        
    with open(output, "w") as f:
        f.write(outputter.output_as_string())
    
    console.print(f"\n[bold green]✔ Compliance Artifact Generated:[/bold green] {output} (CycloneDX v{schema_version})")

    console.print(Panel(
        f"[bold white]📊 Visualize this report:[/bold white]\n"
        f"Drag and drop [cyan]{output}[/cyan] into our secure offline viewer:\n"
        f"👉 [link=https://www.aisbom.io/viewer.html]https://www.aisbom.io/viewer.html[/link]",
        border_style="blue",
        expand=False
    ))

@app.command()
def info():
    """
    Displays application information, pulling from pyproject.toml if available.
    """
    version = description = repository = None

    # First, try to read from pyproject.toml (for development)
    try:
        with open("pyproject.toml", "rb") as f:
            pyproject_data = tomllib.load(f)
        poetry_data = pyproject_data.get("tool", {}).get("poetry", {})
        version = poetry_data.get("version")
        description = poetry_data.get("description")
        repository = poetry_data.get("repository")
    except (FileNotFoundError, tomllib.TOMLDecodeError):
        pass  # Not in a dev environment, so we'll try the installed package

    # If not found in pyproject.toml, try importlib.metadata (for installed package)
    if not version:
        try:
            version = importlib.metadata.version("aisbom")
            # To get other metadata, we'd need to call metadata()
            pkg_metadata = importlib.metadata.metadata("aisbom")
            if not description:
                description = pkg_metadata.get("Summary")
            if not repository:
                repository = pkg_metadata.get("Home-page")
        except importlib.metadata.PackageNotFoundError:
            pass # package not installed

    # Fallbacks
    version = version or "unknown (not installed)"
    description = description or "AI SBOM Generator CLI"
    repository = repository or "https://github.com/Lab700xOrg/aisbom"

    console.print(f"aisbom: {description}")
    console.print(f"Version: {version}")
    console.print(f"Repository: {repository}")

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
        
    console.print(Panel.fit(f"[bold blue]🧪 Generating Test Artifacts in:[/bold blue] {target_path.resolve()}"))
    
    # 1. Create Mock Malware
    mock_malware_path = create_mock_malware_file(target_path)
    console.print(f"  [red]• Created:[/red] {mock_malware_path.name} (Simulates Pickle RCE)")
    
    # 2. Create Mock Legal Risk
    mock_legal_path = create_mock_restricted_file(target_path)
    console.print(f"  [yellow]• Created:[/yellow] {mock_legal_path.name} (Simulates Restrictive License)")
    
    console.print("\n[bold green]Done.[/bold green] Now run: [code]aisbom scan .[/code]")


if __name__ == "__main__":
    app()