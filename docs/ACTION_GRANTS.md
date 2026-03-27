# Action Grants

Portable, signed execution permissions for AI actions.

## Overview

Action Grants are **not a second decision engine**. They package and sign scoped execution permissions issued **only after a PERMIT decision**.

```
Agent Request
      ↓
TrigGuard DecisionEngine
      ↓
PERMIT + DecisionReceipt
      ↓
ActionGrantIssuer
      ↓
Signed ActionGrant
      ↓
Executor verifies grant offline
      ↓
Action executes
```

## DecisionReceipt vs ActionGrant

| Artifact | Purpose | When Created |
|----------|---------|--------------|
| **DecisionReceipt** | Proof of decision | After every authorization |
| **ActionGrant** | Permission for execution | Only after PERMIT |

**DecisionReceipt** = "TrigGuard decided X for reason Y"

**ActionGrant** = "Bearer of this grant may execute action Z within constraints"

## Design Principles

### 1. Narrow Scope

Each grant authorizes exactly one:
- Surface (e.g., `SPEND`)
- Action (e.g., `transfer_money`)
- Resource (e.g., `account_123`)
- Constraint set (e.g., `max_amount: 100`)

**No broad bearer tokens.**

### 2. Short-Lived

Default TTL: **30 seconds**

Grants expire quickly to minimize risk window.

### 3. Cryptographically Signed

Ed25519 signatures (or HMAC-SHA256 fallback).

Executors verify authenticity without network calls.

### 4. Offline Verification

Executors need only:
- Grant payload
- Signature
- Trusted public key

**No policy lookup. No network call.**

### 5. Bound to Decision Artifacts

Every grant includes:
- `policy_version`
- `decision_hash`
- `receipt_hash`

This ensures auditability and replay integrity.

## Usage

### Issuing a Grant

```python
from trigguard.grants import ActionGrantIssuer, GrantConstraints
from trigguard.protocol.decision_contracts import Decision

# Create issuer (use Ed25519 private key in production)
issuer = ActionGrantIssuer(private_key=my_private_key)

# After a PERMIT decision
grant = issuer.issue_grant(
    decision=Decision.PERMIT,
    receipt=receipt,
    request=request,
    constraints=GrantConstraints(
        max_amount=100.0,
        allowed_currency="GBP",
    ),
    ttl_seconds=30,
)

print(grant.to_json())
```

### Verifying a Grant

```python
from trigguard.grants import ActionGrantVerifier

# Create verifier with trusted public key
verifier = ActionGrantVerifier(public_key=trusted_public_key)

# Before executing
result = verifier.verify_grant(
    grant,
    surface="SPEND",
    action="transfer_money",
    execution_input={
        "amount": 50.0,
        "currency": "GBP",
    },
)

if result.valid:
    execute_action()
else:
    reject(result.reason)
```

## Grant Structure

```json
{
  "grant_id": "550e8400-e29b-41d4-a716-446655440000",
  "issuer": "trigguard-kernel",
  "issued_at": "2026-03-27T16:20:00Z",
  "expires_at": "2026-03-27T16:20:30Z",
  "subject": "agent-123",
  "surface": "SPEND",
  "action": "transfer_money",
  "resource": "account_abc",
  "constraints": {
    "max_amount": 100,
    "allowed_currency": "GBP"
  },
  "policy_version": "v1.0.0",
  "decision_hash": "abc123...",
  "receipt_hash": "def456...",
  "metadata": {},
  "signature": "ed25519:..."
}
```

## Constraints

Constraints limit what the grant authorizes:

| Constraint | Description |
|------------|-------------|
| `max_amount` | Maximum monetary value |
| `allowed_currency` | Required currency |
| `allowed_command` | Exact command allowed |
| `allowed_tool_args` | Tool argument restrictions |
| `one_time_use` | Flag for single use |
| `custom` | Custom key-value constraints |

## Verification Checks

`verify_grant()` performs:

1. **Signature** - Cryptographic signature is valid
2. **Expiry** - Grant has not expired
3. **Scope** - Surface, action, resource match
4. **Constraints** - Execution input satisfies limits

All checks must pass.

## Errors

| Error | Cause |
|-------|-------|
| `GrantIssuanceError` | Cannot issue (DENY decision, missing receipt) |
| `GrantExpiredError` | Grant TTL exceeded |
| `GrantSignatureError` | Invalid signature |
| `GrantScopeMismatchError` | Wrong surface/action/resource |
| `GrantConstraintViolationError` | Input violates constraints |

## Security Considerations

1. **Protect private keys** - Issuer private keys are critical secrets
2. **Verify signatures** - Never skip signature verification
3. **Check expiry** - Always validate TTL
4. **Validate scope** - Match surface + action + resource exactly
5. **Enforce constraints** - Check all constraints before execution

## What Grants Don't Do

Grants do NOT:
- Make policy decisions
- Replace the DecisionEngine
- Store state
- Track usage counts (stateless by design)

Grants only prove that a PERMIT was issued with specific scope.

## Integration Pattern

```
┌─────────────────┐
│   AI Agent      │
└────────┬────────┘
         │ request
         ▼
┌─────────────────┐
│ TrigGuard Gate  │
│ (DecisionEngine)│
└────────┬────────┘
         │ PERMIT + Receipt
         ▼
┌─────────────────┐
│  Grant Issuer   │
└────────┬────────┘
         │ Signed ActionGrant
         ▼
┌─────────────────┐
│    Executor     │
│ (Grant Verifier)│
└────────┬────────┘
         │ verified
         ▼
┌─────────────────┐
│  Action Runs    │
└─────────────────┘
```

## Why This Architecture

OAuth won by separating:
- Identity provider
- Client
- Resource server

TrigGuard separates:
- **Policy authority** (DecisionEngine)
- **Agent/requester**
- **Execution target** (Executor)

Using a **portable, signed Action Grant**.

This makes TrigGuard the **authorization layer for AI actions** - not just a guardrail.
