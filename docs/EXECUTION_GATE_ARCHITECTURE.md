# TrigGuard Execution Gate Architecture

**TrigGuard is a deterministic authorization gate for AI actions.**

---

## Architecture

```
┌─────────────────┐
│    AI Agent     │
│   Application   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   TrigGuard     │
│ Execution Gate  │
│                 │
│  ┌───────────┐  │
│  │  Policy   │  │
│  │  Engine   │  │
│  └───────────┘  │
│        │        │
│        ▼        │
│  PERMIT │ DENY  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Real World    │
│   Execution     │
│                 │
│ • Send money    │
│ • Export data   │
│ • Run code      │
│ • Delegate auth │
└─────────────────┘
```

---

## Quick Start

```bash
pip install trigguard
```

### Simple Usage

```python
from trigguard import gate

# Build execution request
request = {
    "surface": "SPEND",
    "action": "transfer_funds",
    "arguments": {"amount": 1000, "currency": "USD"}
}

# Check authorization
decision = gate.check(request)

if decision.permit:
    transfer_funds()
else:
    print(f"Blocked: {decision.reason}")
```

### Decorator Usage

```python
from trigguard import guard

@guard(surface="CODE_EXEC")
def run_shell_command(cmd: str):
    """Protected by TrigGuard. Raises if denied."""
    subprocess.run(cmd, shell=True)

# Function only executes if TrigGuard permits
run_shell_command("rm -rf /tmp/cache")
```

---

## Irreversible Execution Surfaces

TrigGuard protects **irreversible actions** by default with strict evaluation:

| Surface | Description | Risk |
|---------|-------------|------|
| `SPEND` | Financial transactions | Tier 1 |
| `DATA_EXPORT` | Data leaving the system | Tier 1 |
| `CODE_EXEC` | Running arbitrary code | Tier 1 |
| `DELEGATION` | Authority transfer | Tier 1 |
| `IDENTITY_ASSERTION` | Acting as a specific identity | Tier 1 |

### What "Irreversible" Means

Once these actions execute, they cannot be undone:

- **SPEND**: Money sent is money gone
- **DATA_EXPORT**: Data leaked is data compromised
- **CODE_EXEC**: Executed code has real-world effects
- **DELEGATION**: Delegated authority can be abused
- **IDENTITY_ASSERTION**: Identity claims have legal implications

TrigGuard applies **strict policy evaluation** to these surfaces:
- Any CRITICAL signal triggers DENY
- Missing required signals trigger DENY
- **Fail-closed on any error**

---

## Fail-Closed Behavior

**Critical infrastructure rule: If TrigGuard cannot evaluate, execution is DENIED.**

```python
# These scenarios all result in DENY:
# - Policy unavailable
# - Signal frame incomplete
# - Decision engine error
# - Policy version mismatch

decision = gate.check(request)
# If anything goes wrong internally, decision.permit == False
```

This ensures TrigGuard never accidentally permits dangerous actions.

---

## Decision Receipts

Every decision produces a cryptographic receipt:

```python
decision = gate.check(request)

# Audit trail
print(decision.receipt.receipt_hash)
print(decision.receipt.policy_version)
print(decision.receipt.evaluated_at)
```

Receipts enable:
- **Auditability**: Every decision is logged
- **Replay**: Decisions can be replayed for verification
- **Tamper-evidence**: Hash chain prevents modification

---

## Integration Points

### 1. Execution Gate (Primary)

Wrap any irreversible action:

```python
decision = gate.check(request)
if decision.permit:
    execute_action()
```

### 2. Decorator Middleware

Protect functions directly:

```python
@guard(surface="SPEND")
def transfer_money():
    ...
```

### 3. FastAPI Middleware

Protect HTTP endpoints:

```python
app.add_middleware(
    TrigGuardMiddleware,
    surface="DATA_EXPORT"
)
```

### 4. Agent Tool Wrapper

Protect agent tool calls:

```python
@guard(surface="CODE_EXEC")
def run_code(code: str):
    exec(code)
```

---

## The Core Invariant

**Execution cannot happen unless TrigGuard permits it.**

If this invariant holds across all integration points, TrigGuard becomes infrastructure.

If this invariant breaks, TrigGuard becomes just another tool.

---

## For Infrastructure Engineers

TrigGuard is designed like core infrastructure:

| Concept | TrigGuard | Comparison |
|---------|-----------|------------|
| Traffic | Execution gates evaluated | Cloudflare requests/sec |
| Control | Authorization decisions | AWS IAM policies |
| Audit | Decision receipts | Stripe authorization logs |
| Safety | Fail-closed | Circuit breakers |

The key metric: **Execution Gates Evaluated per Day**

This measures how much real-world execution flows through TrigGuard.
