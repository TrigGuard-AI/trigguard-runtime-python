# Execution Surface Registry

## Overview

The Execution Surface Registry is TrigGuard's canonical registry of execution surfaces. It provides:

- **Portable surface identities**: Canonical, namespaced surface IDs
- **Alias resolution**: Map legacy names to canonical IDs
- **Risk classification**: Surfaces organized by risk tier
- **Discovery endpoints**: Well-known URLs for ecosystem integration

This is what transforms TrigGuard from a library into a protocol.

## Why Registry Matters

Without a registry, integrations hardcode surface strings:

```python
# Bad: Magic strings everywhere
@guard(surface="SPEND")
def pay():
    ...

@guard(surface="spend")  # Same? Different?
def transfer():
    ...
```

With a registry, surfaces are canonical:

```python
# Good: Canonical identifiers
@guard(surface="trigguard.spend.transfer")
def pay():
    ...

# Aliases resolve to canonical
@guard(surface="SPEND")  # -> trigguard.spend.transfer
def transfer():
    ...
```

## Surface vs Policy

**Surface Registry** defines WHAT a surface IS:
- Identity (`trigguard.spend.transfer`)
- Risk tier (`IRREVERSIBLE`)
- Constraints schema

**Policy** decides WHETHER it's ALLOWED:
- Based on signals, context, rules
- Changes over time
- Per-tenant or per-agent

Registry is stable. Policy is configurable.

## Canonical Surface IDs

Surface IDs are namespaced, hierarchical identifiers:

```
namespace.category.action
```

### TrigGuard Canonical Surfaces

| Surface ID | Display Name | Risk Tier | Reversible |
|------------|--------------|-----------|------------|
| `trigguard.spend.transfer` | Spend Transfer | IRREVERSIBLE | No |
| `trigguard.spend.authorize` | Spend Authorization | HIGH | Yes |
| `trigguard.data.export` | Data Export | HIGH | No |
| `trigguard.data.delete` | Data Deletion | IRREVERSIBLE | No |
| `trigguard.data.mutate` | Data Mutation | MEDIUM | Yes |
| `trigguard.code.exec` | Code Execution | IRREVERSIBLE | No |
| `trigguard.code.deploy` | Code Deployment | HIGH | Yes |
| `trigguard.identity.assert` | Identity Assertion | IRREVERSIBLE | No |
| `trigguard.identity.grant` | Identity Grant | HIGH | Yes |
| `trigguard.delegation.grant` | Delegation Grant | IRREVERSIBLE | No |
| `trigguard.delegation.revoke` | Delegation Revocation | HIGH | No |
| `trigguard.time.commit` | Time Commitment | HIGH | No |
| `trigguard.api.external` | External API Call | MEDIUM | Yes |
| `trigguard.api.internal` | Internal API Call | LOW | Yes |
| `trigguard.tool.invoke` | Tool Invocation | MEDIUM | Yes |
| `trigguard.ai.inference` | AI Inference | LOW | Yes |
| `trigguard.ai.finetune` | AI Finetuning | HIGH | No |
| `trigguard.retrieval.search` | Retrieval Search | LOW | Yes |

### Third-Party Namespaces

Integrations can register their own surfaces:

```python
from trigguard.registry import get_global_surface_registry, ExecutionSurfaceDefinition, SurfaceRiskTier

registry = get_global_surface_registry()

# OpenAI tool surface
openai_surface = ExecutionSurfaceDefinition(
    surface_id="openai.tool.call",
    namespace="openai",
    display_name="OpenAI Tool Call",
    description="Call an OpenAI-registered tool",
    risk_tier=SurfaceRiskTier.MEDIUM,
    reversible=True,
    tags=["openai", "tool", "ai"],
)
registry.register(openai_surface)
```

## Aliases and Normalization

Legacy surface names are resolved to canonical IDs:

```python
from trigguard.registry import normalize_surface

# All resolve to trigguard.spend.transfer
normalize_surface("SPEND")           # -> trigguard.spend.transfer
normalize_surface("spend")           # -> trigguard.spend.transfer
normalize_surface("transfer")        # -> trigguard.spend.transfer
normalize_surface("payment")         # -> trigguard.spend.transfer

# Already canonical
normalize_surface("trigguard.spend.transfer")  # -> trigguard.spend.transfer

# Unknown surfaces
normalize_surface("unknown_thing")   # -> unknown.unknown_thing
```

## Discovery Manifest

Tools and executors declare their capabilities via `DiscoveryManifest`:

```python
from trigguard.discovery import DiscoveryManifest, SurfaceDiscoveryRecord

manifest = DiscoveryManifest(issuer="my-payment-tool")

manifest.add_surface(SurfaceDiscoveryRecord(
    surface_id="trigguard.spend.transfer",
    supported_actions=["transfer", "refund"],
    resource_types=["bank_account", "wallet"],
    grant_required=True,
    verifier_required=True,
    constraint_schema=ConstraintSchema(
        supports_max_amount=True,
        supports_currency=True,
    ),
))

# Export for advertisement
manifest.to_dict()
```

## Well-Known Endpoints

TrigGuard exposes registry and discovery via standardized endpoints:

### GET /.well-known/trigguard-surfaces

Returns canonical surface definitions:

```json
{
  "issuer": "trigguard",
  "version": "1.0",
  "updated_at": "2026-03-27T12:00:00Z",
  "surface_count": 18,
  "surfaces": [
    {
      "surface_id": "trigguard.spend.transfer",
      "namespace": "trigguard",
      "display_name": "Spend Transfer",
      "description": "Transfer of monetary value",
      "risk_tier": "irreversible",
      "reversible": false,
      "tags": ["money", "payment", "irreversible"],
      "requires_grant": true
    }
  ]
}
```

### GET /.well-known/trigguard-discovery

Returns this instance's capability manifest:

```json
{
  "issuer": "trigguard",
  "version": "1.0",
  "updated_at": "2026-03-27T12:00:00Z",
  "surface_count": 18,
  "surfaces": [
    {
      "surface_id": "trigguard.spend.transfer",
      "supported_actions": [],
      "resource_types": [],
      "verifier_required": true,
      "grant_required": true,
      "constraint_schema": {
        "max_amount": {"type": "number"},
        "currency": {"type": "string"}
      }
    }
  ]
}
```

### GET /.well-known/trigguard-surfaces/{surface_id}

Returns a specific surface definition:

```json
{
  "surface_id": "trigguard.spend.transfer",
  "namespace": "trigguard",
  "display_name": "Spend Transfer",
  "risk_tier": "irreversible",
  "reversible": false,
  "requires_grant": true,
  "default_constraints": {"max_amount": null, "allowed_currency": null},
  "examples": ["bank transfer", "payment", "wire transfer"]
}
```

### GET /.well-known/trigguard-surfaces-by-risk/{risk_tier}

Returns surfaces filtered by risk tier:

```json
{
  "risk_tier": "irreversible",
  "surface_count": 6,
  "surfaces": [
    {"surface_id": "trigguard.spend.transfer", "display_name": "Spend Transfer"},
    {"surface_id": "trigguard.code.exec", "display_name": "Code Execution"},
    {"surface_id": "trigguard.data.delete", "display_name": "Data Deletion"}
  ]
}
```

## Grants and surface_id

Action Grants bind to canonical surface IDs:

```python
from trigguard.grants import ActionGrant

grant = ActionGrant(
    surface="SPEND",  # Alias allowed for legacy compatibility
    action="transfer",
    ...
)

# Property normalizes to canonical
grant.surface_id  # -> "trigguard.spend.transfer"

# Check registration
grant.is_registered_surface  # -> True
```

## SDK Integration

The SDK normalizes surfaces through the registry:

```python
from trigguard.sdk.gate import discover_surface, get_surface_risk_tier

# Discover canonical ID
discover_surface("SPEND")  # -> "trigguard.spend.transfer"
discover_surface("openai_tool")  # -> None (unless registered)

# Get risk tier
get_surface_risk_tier("trigguard.code.exec")  # -> "irreversible"
```

## Tool Manifest

Tools can self-describe their surfaces:

```python
from trigguard.discovery import ToolSurfaceManifest, declares_surface

# From tool definition (OpenAI/Anthropic/MCP style)
manifest = ToolSurfaceManifest.from_tool_definition({
    "name": "send_payment",
    "parameters": {"amount": {"type": "number"}, "currency": {"type": "string"}},
})

# From callable
def transfer_money(amount: float, currency: str) -> bool:
    ...

manifest = ToolSurfaceManifest.from_callable(transfer_money)

# Via decorator
@declares_surface("trigguard.spend.transfer")
def pay():
    ...
```

## Risk Tiers

| Tier | Value | Requires Grant | Fail-Closed |
|------|-------|----------------|-------------|
| LOW | `low` | No | No |
| MEDIUM | `medium` | No | No |
| HIGH | `high` | Yes | No |
| IRREVERSIBLE | `irreversible` | Yes | Yes |

## Why This Helps Ecosystem Adoption

1. **Portable identities**: Any executor can understand surface IDs
2. **Discovery**: Tools advertise capabilities, TrigGuard governs them
3. **Ecosystem growth**: Third-party surfaces register with namespaces
4. **Grant standardization**: Grants bind to canonical IDs, not magic strings
5. **Interoperability**: Multiple TrigGuard instances share surface semantics

## Summary

The Execution Surface Registry transforms TrigGuard from:

```
a library people manually wire
```

into:

```
a control plane agents and tools can plug into
```

Surfaces are the lingua franca of execution authorization.
