# Decision Authority Rule

TrigGuard has exactly **one decision authority**: the Kernel.

## The Rule

> Only the kernel may decide PERMIT / DENY / SILENCE.
>
> Everything else may only normalize, package, verify, enforce, transport, or log.
> Never decide.

This is the rule that keeps TrigGuard trustworthy at scale.

## Why This Matters

If authorization logic leaks outside the kernel:

- **Determinism breaks** — same input gives different outputs
- **Replayability breaks** — can't replay decisions for audit
- **Auditability breaks** — can't trace why something was allowed
- **Trust breaks** — no single source of truth

You go from:

```
One decision engine
```

To:

```
A pile of hidden policy logic scattered across the codebase
```

That is how infrastructure systems rot.

## Architecture Layers

```
                 AI AGENT
                     │
                     │ request action
                     ▼
              Decision Engine
                 (kernel)          ← ONLY HERE: PERMIT/DENY/SILENCE
                     │
                     │ deterministic decision
                     ▼
             Decision Receipt
                     │
                     │ signed evidence
                     ▼
                Action Grant
            portable authorization
                     │
                     │ verified
                     ▼
              Verification SDK     ← verify, never decide
                     │
                     │ enforce
                     ▼
                 Executor          ← enforce, never decide
                     │
                     │ allow execution
                     ▼
                  ACTION
           (API / tool / system)
```

## What Each Layer May Do

### Kernel (`trigguard/kernel/`, `trigguard/engine/`)

**MAY:**
- Evaluate policies
- Calculate risk scores
- Make PERMIT/DENY/SILENCE decisions
- Generate DecisionReceipts

**MUST:**
- Remain pure (no network, no database)
- Be deterministic (same input = same output)
- Be the single source of truth

### Protocol (`trigguard/protocol/`, `trigguard/grants/`)

**MAY:**
- Define portable objects (ActionGrant, DecisionReceipt)
- Define type schemas
- Implement serialization

**MUST NOT:**
- Make authorization decisions
- Implement policy logic

### Verification (`trigguard/verification/`)

**MAY:**
- Verify signatures
- Check expiry
- Validate grant structure
- Return verification results

**MUST NOT:**
- Make authorization decisions
- Evaluate policies
- Implement risk thresholds

### Executor (`trigguard/executor/`)

**MAY:**
- Verify grants using Verification SDK
- Enforce constraints
- Execute actions when grant is valid
- Emit execution receipts

**MUST NOT:**
- Make authorization decisions
- Evaluate policies
- Implement fallback rules

### SDK (`trigguard/sdk/`)

**MAY:**
- Provide decorators (@requires_grant)
- Wrap verification calls
- Format responses

**MUST NOT:**
- Make authorization decisions
- Implement inline policy checks
- Add hidden authorization rules

### Server (`trigguard/server/`)

**MAY:**
- Expose HTTP endpoints
- Handle requests
- Call kernel for decisions

**MUST NOT:**
- Make authorization decisions
- Implement middleware authorization
- Add URL-based policy rules

## Forbidden Patterns Outside Kernel

```python
# ❌ FORBIDDEN in SDK/Executor/Server
if risk_score > 0.8:
    return DENY

# ❌ FORBIDDEN
return Decision.PERMIT

# ❌ FORBIDDEN
decision = Decision.DENY

# ❌ FORBIDDEN
if user.role == "admin":
    allowed = True
```

## Allowed Patterns Outside Kernel

```python
# ✅ ALLOWED - verification
result = verifier.verify_grant(grant)

# ✅ ALLOWED - enforcement
if not result.valid:
    raise GrantVerificationError(...)

# ✅ ALLOWED - delegation
decision = kernel.evaluate(frame)

# ✅ ALLOWED - type hints
def process(decision: Decision) -> None:

# ✅ ALLOWED - reading decisions made by kernel
if decision.allowed:
    execute_action()
```

## CI Enforcement

These rules are enforced by CI tests:

- `tests/test_decision_authority_boundary.py` — blocks decision logic outside kernel
- `tests/test_kernel_import_boundary.py` — blocks kernel importing outer layers

If your PR fails these tests, you need to move the logic into the kernel.

## The Long-Term Promise

Once the kernel stabilizes:

| Layer | Change Frequency |
|-------|------------------|
| Kernel | Frozen (bug fixes only) |
| Protocol | Slow (versioned) |
| Verification | Medium |
| SDK | Fast |
| Integrations | Wild west |

The kernel becomes the stable core.
Everything else can evolve freely around it.

## Real-World Examples

**Linux kernel:**
- Stable core scheduler
- Drivers live outside

**Kubernetes:**
- Core scheduler stable
- Controllers outside

**OAuth:**
- Spec frozen
- Libraries everywhere

TrigGuard follows the same pattern.
