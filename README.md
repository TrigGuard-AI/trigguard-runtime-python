# TrigGuard (Python runtime)

> **Canonical repository (GitHub):**  
> **[https://github.com/TrigGuard-AI/trigguard-runtime-python](https://github.com/TrigGuard-AI/trigguard-runtime-python)**
>
> If you are viewing this on **GitLab** (`TrigGuardAI/trigguard-kernel`), treat it as a **legacy mirror** (or archived read-only copy). **Do not** use GitLab as a competing canonical — issues, pull requests, and releases use **GitHub** only.

## Role in the TrigGuard Ecosystem

This repository provides an **alternate Python runtime** implementation of the TrigGuard protocol (gates, policy evaluation, HTTP services). It does **not** define the protocol contract.

- **Protocol specification:** [github.com/TrigGuard-AI/trigguard-protocol](https://github.com/TrigGuard-AI/trigguard-protocol)
- **Reference runtime:** [github.com/TrigGuard-AI/TrigGuard](https://github.com/TrigGuard-AI/TrigGuard) (TrigGuard monorepo)

**Normative protocol semantics** live in **trigguard-protocol** only. This package implements that contract.

See [`docs/CANONICAL_REPOSITORY.md`](docs/CANONICAL_REPOSITORY.md) for GitLab legacy remote, mirror options, and naming notes.

---

**TrigGuard is an execution authorization layer for AI agents.**

It sits between AI systems and real-world actions, ensuring that dangerous
or irreversible operations only execute with explicit authorization.

```
AI Agent
   ↓
TrigGuard Gate
   ↓
Execution
```

---

## Installation

```bash
pip install trigguard
```

---

## Quick Start

### Simple Gate Check

```python
from trigguard import gate

# Check before executing
decision = gate.check({
    "surface": "SPEND",
    "action": "transfer_funds",
    "arguments": {"amount": 1000}
})

if decision.permit:
    transfer_funds()
else:
    print(f"Blocked: {decision.reason}")
```

### Guard Decorator

```python
from trigguard import guard

@guard(surface="CODE_EXEC")
def run_shell(cmd: str):
    """Protected by TrigGuard. Raises if denied."""
    subprocess.run(cmd, shell=True)

# Function only executes if TrigGuard permits
run_shell("rm -rf /tmp/cache")
```

---

## Architecture

```
┌─────────────────┐
│    AI Agent     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   TrigGuard     │
│ Execution Gate  │
│                 │
│  Policy Engine  │
│        │        │
│  PERMIT │ DENY  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Real World    │
│   Execution     │
└─────────────────┘
```

---

## Core Capabilities

| Capability | Description |
|------------|-------------|
| **Execution Gating** | All actions pass through authorization gate |
| **Decision Receipts** | Cryptographic proof of every decision |
| **Deterministic Replay** | Decisions can be replayed for verification |
| **Irreversible Protection** | Strict evaluation for dangerous actions |
| **Policy Network** | Distributed policy updates via signed bundles |
| **Fail-Closed** | Errors result in DENY, never accidental permit |

---

## Protected Surfaces

TrigGuard protects irreversible actions by default:

| Surface | Risk | Description |
|---------|------|-------------|
| `SPEND` | Tier 1 | Financial transactions |
| `DATA_EXPORT` | Tier 1 | Data leaving the system |
| `CODE_EXEC` | Tier 1 | Running arbitrary code |
| `DELEGATION` | Tier 1 | Authority transfer |
| `IDENTITY_ASSERTION` | Tier 1 | Acting as specific identity |

---

## CLI Tools

```bash
# Verify a decision receipt
trigguard-audit verify receipt.json

# Replay a decision
trigguard-audit replay receipt.json --frame frame.json

# Explain a decision
trigguard-audit explain receipt.json

# Inspect policy
trigguard-audit inspect-policy

# Export decision logs
trigguard-audit export-decisions logs.jsonl
```

---

## Integrations

### FastAPI Middleware

```python
from trigguard.integrations import TrigGuardMiddleware

app.add_middleware(
    TrigGuardMiddleware,
    surface="DATA_EXPORT"
)
```

### Agent Tool Guard

```python
from trigguard.integrations import guarded_tool

@guarded_tool(surface="CODE_EXEC")
def run_code(code: str):
    exec(code)
```

---

## The Key Metric

**Execution Gates Evaluated per Day**

This is how TrigGuard proves it's infrastructure:
- Cloudflare → requests/sec
- Stripe → payment volume
- TrigGuard → gates evaluated

---

## Documentation

- [Execution Gate Architecture](docs/EXECUTION_GATE_ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Signal Taxonomy](docs/SIGNAL_TAXONOMY.md)

---

## License

See [LICENSE](LICENSE) for details.

---

## Security

See [SECURITY.md](SECURITY.md) for security policies and reporting vulnerabilities.
