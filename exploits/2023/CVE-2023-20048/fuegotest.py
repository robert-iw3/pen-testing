import click
from fuegotest.core import FuegoTest
from rich.console import Console
from rich.progress import Progress
import logging


from rich.logging import RichHandler
logging.basicConfig(level=logging.INFO, handlers=[RichHandler()])

console = Console()

@click.group()
def cli():
    """FuegoTest: Detect devices potentially vulnerable to CVE-2023-20048 in Cisco Firepower Management Center."""
    pass

@cli.command()
@click.option('--fmc-url', prompt=True, help='FMC web services interface URL.')
@click.option('--fmc-user', prompt=True, help='Username for the FMC.')
@click.option('--fmc-pass', prompt=True, hide_input=True, help='Password for the FMC.')
@click.option('--domain-id', prompt=True, help='Domain ID for the FMC instance.')
def detect(fmc_url, fmc_user, fmc_pass, domain_id):
    """
    Detect potentially vulnerable devices in a specified Cisco Firepower Management Center.
    """
    fuego_test = FuegoTest(fmc_url, fmc_user, fmc_pass, domain_id)
    
    with Progress() as progress:
        task1 = progress.add_task("[cyan]Authenticating...", total=1)
        fuego_test.authenticate()
        progress.update(task1, advance=1)

        task2 = progress.add_task("[green]Fetching devices...", total=1)
        vulnerable_devices = fuego_test.detect_vulnerable_devices(progress, task2)
        progress.update(task2, advance=1)
        
    if vulnerable_devices:
        console.print("\n[bold magenta]Potentially Vulnerable Devices:[/bold magenta]")
        for device in vulnerable_devices:
            console.print(f"[yellow]- {device}[/yellow]")
    else:
        console.print("\n[bold green]No potentially vulnerable devices found.[/bold green]")

if __name__ == '__main__':
    cli()
