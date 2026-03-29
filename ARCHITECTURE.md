# TrigGuard Architecture

TrigGuard Kernel is the canonical runtime for the TrigGuard protocol.

## Responsibilities

- **Decision Authority** — Only the kernel produces PERMIT, DENY, or SILENCE decisions
- **Surface Registry** — Canonical namespace for execution surfaces (`trigguard.<domain>.<action>`)
- **Grant Verification** — Cryptographic validation of action grants
- **Executor Enforcement** — Runtime boundary that enforces decisions
- **Protocol Discovery** — Well-known endpoints for ecosystem integration

## Architecture Layers

```
┌─────────────────────────────────────┐
│            server                   │  HTTP endpoints, well-known routes
├─────────────────────────────────────┤
│            runtime                  │  Executor service, request handling
├─────────────────────────────────────┤
│            sdk                      │  @requires_grant, protect_tools()
├─────────────────────────────────────┤
│            executor                 │  Enforcement boundary
├─────────────────────────────────────┤
│            verification             │  Grant signature verification
├─────────────────────────────────────┤
│            registry                 │  Surface definitions, aliases
├─────────────────────────────────────┤
│            protocol                 │  Core primitives, decision types
└─────────────────────────────────────┘
```

## The One Rule

> **Only the kernel may produce PERMIT or DENY decisions.**

Other repositories (trigguard-platform, trigguard-infra, external integrations) may:
- Implement clients
- Deploy services
- Create wrappers

But they **MUST NOT** implement policy logic. All authorization flows through the kernel.

## Package Structure

```
trigguard/
├── core/           # Decision types, surfaces
├── grants/         # ActionGrant, grant verification
├── protocol/       # Protocol primitives
├── registry/       # Surface registry, risk tiers
├── discovery/      # Tool manifest, discovery contract
├── verification/   # Verifier SDK, public key discovery
├── executor/       # Executor boundary, contracts
├── runtime/        # Executor service (FastAPI)
├── sdk/            # Decorators, protect_tools()
├── keys/           # Key rotation, distribution
├── cli/            # Command-line interface
├── telemetry/      # Decision receipts, audit logs
└── server/         # HTTP server, well-known endpoints
```

## Integration Points

### For Agent Developers

```python
from trigguard.sdk import requires_grant, protect_tools

# Decorator-based
@requires_grant("trigguard.spend.transfer")
def transfer_funds(amount: float):
    ...

# Automatic protection
protect_tools(agent)  # All tools become TrigGuard-secured
```

### For Platform Operators

```python
from trigguard.runtime import TrigGuardRuntime

runtime = TrigGuardRuntime()
runtime.start()  # Serves on :8080
```

### For Security Teams

```python
from trigguard.telemetry import DecisionReceipt

# Audit all decisions
receipts = DecisionReceipt.query(
    surface="trigguard.spend.*",
    decision="PERMIT",
    since="2026-03-01"
)
```

## Protocol Discovery

All TrigGuard-compatible services expose:

| Endpoint | Purpose |
|----------|---------|
| `/.well-known/trigguard-surfaces` | List registered surfaces |
| `/.well-known/trigguard-discovery` | Discovery manifest |
| `/.well-known/trigguard-protocol` | Protocol metadata |
| `/.well-known/trigguard-keys` | Public keys for verification |

## Version Policy

- **v0.x** — Protocol stabilization, breaking changes allowed
- **v1.x** — Stable protocol, backward-compatible changes only
- **v2.x** — Reserved for major protocol evolution

Current version: **0.2.0**
