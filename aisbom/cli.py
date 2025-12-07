import typer
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot5, JsonV1Dot6


# Import our new logic engine
from .scanner import DeepScanner

app = typer.Typer()
console = Console()

@app.callback(invoke_without_command=True)
def main(
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
        table.add_column("Risk Level", style="bold red")
        table.add_column("Metadata", style="dim")
        
        for art in results['artifacts']:
            risk_style = "green" if "LOW" in art['risk_level'] else "red"
            table.add_row(
                art['name'], 
                art['framework'], 
                f"[{risk_style}]{art['risk_level']}[/{risk_style}]", 
                str(art.get('details', ''))[:40] + "..."
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
    
    # Add Models
    for art in results['artifacts']:
        c = Component(
            name=art['name'],
            type=ComponentType.MACHINE_LEARNING_MODEL,
            # We shove our risk assessment into the description for now
            description=f"Risk: {art['risk_level']} | Framework: {art['framework']}"
        )
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

if __name__ == "__main__":
    app()