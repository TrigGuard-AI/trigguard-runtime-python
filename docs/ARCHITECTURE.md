# TrigGuard Architecture

TrigGuard is an **authorization layer** that sits between AI agents and real-world actions.

## Execution Model

```
┌─────────────────┐
│    AI Agent     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ TrigGuard Gate  │  ← Authorization checkpoint
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Decision Engine │  ← Kernel (deterministic)
│                 │
│  ├─ signals     │
│  ├─ constraints │
│  └─ policy      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  PERMIT / DENY  │  ← Cryptographic receipt
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Action Executed │  ← Only if PERMIT
└─────────────────┘
```

## Design Principles

| Principle | Implementation |
|-----------|----------------|
| **Single decision authority** | Only `DecisionEngine` can emit PERMIT/DENY |
| **Deterministic decisions** | Same inputs → same outputs, always |
| **Cryptographic receipts** | Every decision has verifiable hash chain |
| **Replayable decisions** | Any decision can be audited and replayed |
| **Fail-closed execution** | Errors → DENY, never PERMIT |

## Architectural Boundaries

```
KERNEL (isolated, no external deps)
├── authority/      → DecisionEngine
├── protocol/       → Contracts, receipts, hashing
├── signals/        → SignalFrame, types
├── constraints/    → Constraint evaluation
├── surfaces/       → Execution surfaces
└── aggregation/    → Risk aggregation

EXTERNAL LAYERS (can import kernel)
├── sdk/            → gate, guard decorator
├── server/         → HTTP service
├── integrations/   → LangChain, FastAPI guards
├── cache/          → Decision caching
├── observability/  → Tracing, metrics
├── ratelimit/      → Rate limiting
├── ha/             → High availability
└── policy/         → Multi-tenant, sync
```

## 10-Second Demo

```python
from trigguard import guard

@guard(surface="SPEND")
def transfer_money(amount: float):
    bank.send(amount)

transfer_money(100)  # TrigGuard evaluates → PERMIT or DENY
```

## One-Line Explanation

> **TrigGuard is an authorization layer for AI actions.**

Not "AI safety tool". Not "guardrails".  
Authorization is a known infrastructure category.
