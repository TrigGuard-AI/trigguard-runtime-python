"""
TrigGuard CLI

Command-line interface for TrigGuard operations:
- surfaces: List registered execution surfaces
- verify: Verify a grant token
- inspect: Inspect grant contents
- server: Start the runtime server
- keys: Key management commands
"""

import json
import sys
from typing import Optional

import click

from trigguard import __version__
from trigguard.registry import get_global_surface_registry, SurfaceRiskTier


@click.group()
@click.version_option(version=__version__, prog_name="trigguard")
def cli():
    """TrigGuard - Execution authorization for AI agents."""
    pass


# ============================================================================
# Surfaces Commands
# ============================================================================


@cli.group()
def surfaces():
    """Manage execution surfaces."""
    pass


@surfaces.command("list")
@click.option("--format", "-f", type=click.Choice(["table", "json"]), default="table")
@click.option("--risk-tier", "-r", type=str, help="Filter by risk tier")
def surfaces_list(format: str, risk_tier: Optional[str]):
    """List all registered execution surfaces."""
    registry = get_global_surface_registry()
    all_surfaces = registry.list_all()

    # Filter by risk tier if specified
    if risk_tier:
        try:
            tier = SurfaceRiskTier[risk_tier.upper()]
            all_surfaces = [s for s in all_surfaces if s.risk_tier == tier]
        except KeyError:
            click.echo(f"Unknown risk tier: {risk_tier}", err=True)
            sys.exit(1)

    if format == "json":
        output = []
        for surface in all_surfaces:
            output.append(
                {
                    "id": surface.surface_id,
                    "risk_tier": surface.risk_tier.name,
                    "description": surface.description,
                }
            )
        click.echo(json.dumps(output, indent=2))
    else:
        # Table format
        click.echo(f"{'Surface ID':<40} {'Risk Tier':<15} {'Description'}")
        click.echo("-" * 80)
        for surface in sorted(all_surfaces, key=lambda s: s.surface_id):
            desc = (surface.description or "")[:30]
            click.echo(f"{surface.surface_id:<40} {surface.risk_tier.name:<15} {desc}")

    click.echo(f"\nTotal: {len(all_surfaces)} surfaces")


@surfaces.command("info")
@click.argument("surface_id")
def surfaces_info(surface_id: str):
    """Show detailed information about a surface."""
    registry = get_global_surface_registry()

    # Resolve aliases
    resolved = registry.resolve_alias(surface_id)
    if not resolved:
        click.echo(f"Surface not found: {surface_id}", err=True)
        sys.exit(1)

    surface = registry.get(resolved)
    if not surface:
        click.echo(f"Surface not found: {resolved}", err=True)
        sys.exit(1)

    click.echo(f"Surface ID:    {surface.surface_id}")
    click.echo(f"Risk Tier:     {surface.risk_tier.name}")
    click.echo(f"Description:   {surface.description or 'N/A'}")
    # Find aliases that resolve to this surface
    aliases = [a for a, s in getattr(registry, "_aliases", {}).items() if s == resolved]
    click.echo(f"Aliases:       {', '.join(aliases) or 'None'}")
    if surface_id != resolved:
        click.echo(f"Resolved from: {surface_id}")


@surfaces.command("aliases")
def surfaces_aliases():
    """List all surface aliases."""
    registry = get_global_surface_registry()
    # Access internal aliases dict
    aliases = getattr(registry, "_aliases", {})

    click.echo(f"{'Alias':<40} {'Resolves To'}")
    click.echo("-" * 80)
    for alias, target in sorted(aliases.items()):
        click.echo(f"{alias:<40} {target}")

    click.echo(f"\nTotal: {len(aliases)} aliases")


# ============================================================================
# Verify Commands
# ============================================================================


@cli.command()
@click.argument("token")
@click.option("--format", "-f", type=click.Choice(["human", "json"]), default="human")
def verify(token: str, format: str):
    """Verify a grant token."""
    from trigguard.verification import TrigGuardVerifierSDK

    sdk = TrigGuardVerifierSDK()
    result = sdk.verify(token)

    if format == "json":
        click.echo(
            json.dumps(
                {
                    "valid": result.valid,
                    "reason": result.reason,
                    "grant": result.grant.to_dict() if result.grant else None,
                },
                indent=2,
            )
        )
    else:
        if result.valid:
            click.echo("✓ Grant is VALID")
            if result.grant:
                click.echo(f"  Surface: {result.grant.surface_id}")
                click.echo(f"  Issuer:  {result.grant.issuer}")
                click.echo(f"  Expires: {result.grant.expires_at}")
        else:
            click.echo("✗ Grant is INVALID")
            click.echo(f"  Reason: {result.reason}")

    sys.exit(0 if result.valid else 1)


@cli.command()
@click.argument("token")
def inspect(token: str):
    """Inspect grant token contents without verification."""
    import base64

    try:
        # Decode as JWT (header.payload.signature)
        parts = token.split(".")
        if len(parts) != 3:
            click.echo("Invalid token format (expected JWT)", err=True)
            sys.exit(1)

        # Decode payload
        payload = parts[1]
        # Add padding if needed
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        data = json.loads(decoded)

        click.echo("Grant Token Contents:")
        click.echo(json.dumps(data, indent=2))

    except Exception as e:
        click.echo(f"Failed to decode token: {e}", err=True)
        sys.exit(1)


# ============================================================================
# Server Commands
# ============================================================================


@cli.command()
@click.option("--host", "-h", default="0.0.0.0", help="Host to bind to")
@click.option("--port", "-p", default=8080, type=int, help="Port to bind to")
@click.option("--log-level", "-l", default="INFO", help="Log level")
def server(host: str, port: int, log_level: str):
    """Start the TrigGuard runtime server."""
    from trigguard.runtime import TrigGuardRuntime
    from trigguard.runtime.server import RuntimeConfig

    config = RuntimeConfig(host=host, port=port, log_level=log_level)
    runtime = TrigGuardRuntime(config=config)

    click.echo(f"Starting TrigGuard Runtime on {host}:{port}")
    runtime.start()


# ============================================================================
# Keys Commands
# ============================================================================


@cli.group()
def keys():
    """Manage verification keys."""
    pass


@keys.command("list")
@click.option(
    "--format", "-f", type=click.Choice(["table", "json", "jwks"]), default="table"
)
def keys_list(format: str):
    """List registered public keys."""
    from trigguard.keys import KeyRotationManager

    manager = KeyRotationManager()
    # In real implementation, this would load keys from storage
    valid_keys = manager.list_valid_keys()

    if format == "jwks":
        click.echo(json.dumps(manager.to_jwks(), indent=2))
    elif format == "json":
        click.echo(
            json.dumps(
                [
                    {
                        "key_id": k.key_id,
                        "status": k.status.name,
                        "algorithm": k.algorithm,
                        "created_at": k.created_at.isoformat(),
                    }
                    for k in valid_keys
                ],
                indent=2,
            )
        )
    else:
        click.echo(f"{'Key ID':<20} {'Status':<12} {'Algorithm':<10} {'Created'}")
        click.echo("-" * 60)
        for key in valid_keys:
            click.echo(
                f"{key.key_id:<20} {key.status.name:<12} {key.algorithm:<10} {key.created_at.date()}"
            )

    click.echo(f"\nTotal: {len(valid_keys)} keys")


# ============================================================================
# Info Command
# ============================================================================


@cli.command()
def info():
    """Show TrigGuard runtime information."""
    registry = get_global_surface_registry()

    click.echo("TrigGuard Kernel")
    click.echo(f"  Version:            {__version__}")
    click.echo(f"  Protocol Version:   1.0")
    click.echo(f"  Surfaces:           {len(registry.list_all())}")
    click.echo()
    click.echo("Endpoints:")
    click.echo("  /.well-known/trigguard-surfaces")
    click.echo("  /.well-known/trigguard-protocol")
    click.echo("  /.well-known/trigguard-keys")
    click.echo("  /.well-known/trigguard-runtime")


def main():
    """Entry point."""
    cli()


if __name__ == "__main__":
    main()
