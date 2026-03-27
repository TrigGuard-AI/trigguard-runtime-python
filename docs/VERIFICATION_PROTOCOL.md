# TrigGuard Verification Protocol

Portable verification protocol for AI action authorization.

## What Problem This Solves

AI agents need authorization before executing actions. But:

1. **Decision ≠ Execution Permission** - A policy decision saying "PERMIT" is not the same as a signed, portable permission that can be verified anywhere.

2. **Verification Must Work Offline** - If executors must call the authorization service for every action, the system becomes brittle and centralized.

3. **Third Parties Need Trust** - External systems need to verify TrigGuard grants without trusting TrigGuard's live service.

This protocol solves these problems by making authorization:
- **Portable** - Grants can be verified anywhere
- **Offline** - No network call required for verification
- **Auditable** - Every grant links to its origin decision

## Key Artifacts

### DecisionReceipt vs ActionGrant

| Artifact | Purpose | When Created | Verifiable By |
|----------|---------|--------------|---------------|
| **DecisionReceipt** | Proof that a decision was made | After every evaluation | TrigGuard |
| **ActionGrant** | Permission to execute an action | Only after PERMIT | Anyone with public keys |

**DecisionReceipt** = "TrigGuard decided X for reason Y"

**ActionGrant** = "Bearer of this grant may execute action Z within constraints"

## Public Key Discovery

### Endpoint

```
GET /.well-known/trigguard-keys
```

### Response

```json
{
  "issuer": "trigguard",
  "updated_at": "2026-03-27T12:00:00Z",
  "keys": [
    {
      "kid": "tg-root-1",
      "alg": "Ed25519",
      "public_key": "base64-encoded-key",
      "status": "active",
      "created_at": "2026-01-01T00:00:00Z"
    }
  ]
}
```

### Fields

| Field | Description |
|-------|-------------|
| `kid` | Key ID for rotation support |
| `alg` | Algorithm (Ed25519 or HMAC-SHA256) |
| `public_key` | Base64-encoded public key |
| `status` | Key status: active, rotated, revoked |
| `created_at` | When the key was created |

### Caching

Executors should:
1. Fetch keys once at startup
2. Cache the key set
3. Verify grants using cached keys
4. Refresh periodically (recommended: hourly)

## Grant Verification Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    BOOTSTRAP (once)                          │
├─────────────────────────────────────────────────────────────┤
│  1. Executor fetches /.well-known/trigguard-keys            │
│  2. Executor caches key set                                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                VERIFICATION (per grant)                      │
├─────────────────────────────────────────────────────────────┤
│  1. Receive ActionGrant                                     │
│  2. Verify signature using cached keys                      │
│  3. Check expiry                                            │
│  4. Validate scope (surface, action, resource)              │
│  5. Check constraints against execution input               │
│  6. If all pass → allow execution                           │
│  7. If any fail → deny execution                            │
└─────────────────────────────────────────────────────────────┘
```

## ActionGrant Structure

```json
{
  "grant_id": "550e8400-e29b-41d4-a716-446655440000",
  "issuer": "trigguard",
  "kid": "tg-root-1",
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

### Required Fields

| Field | Description |
|-------|-------------|
| `grant_id` | Unique identifier (UUID) |
| `issuer` | Who issued the grant |
| `kid` | Key ID for signature verification |
| `issued_at` | When the grant was issued (ISO 8601) |
| `expires_at` | When the grant expires (ISO 8601) |
| `surface` | Execution surface |
| `action` | Action authorized |
| `policy_version` | Policy version at time of decision |
| `decision_hash` | Hash of the origin decision |
| `receipt_hash` | Hash of the DecisionReceipt |
| `signature` | Cryptographic signature |

## Executor Verification Contract

The ExecutorVerificationContract defines how executors verify grants:

```python
from trigguard.executor import ExecutorVerificationContract
from trigguard.verification import TrigGuardVerifierSDK

# Setup (once)
sdk = TrigGuardVerifierSDK()
sdk.load_key_set(cached_keys)
contract = ExecutorVerificationContract(sdk)

# Before every execution
decision = contract.verify_before_execute(
    grant,
    surface="SPEND",
    action="transfer_money",
    execution_input={"amount": 100, "currency": "GBP"},
)

if decision.allowed:
    # Safe to execute
    result = execute_action()
    log_audit(decision.to_audit_dict())
else:
    # Do not execute
    log_rejection(decision.reason)
```

### ExecutorDecision

The contract returns an `ExecutorDecision`:

```python
@dataclass
class ExecutorDecision:
    allowed: bool
    reason: str
    grant_id: str
    receipt_hash: str
    decision_hash: str
    verified_at: str
    issuer: str
    kid: str
    checks: dict
```

### Audit Fields

The decision includes audit-safe fields:

```python
audit = decision.to_audit_dict()
# {
#     "allowed": True,
#     "grant_id": "...",
#     "receipt_hash": "...",
#     "decision_hash": "...",
#     "verified_at": "...",
#     "issuer": "trigguard",
#     "kid": "tg-root-1",
# }
```

## Offline Verification Model

```
┌────────────────────┐
│  TrigGuard Server  │
│  (online once)     │
└────────┬───────────┘
         │ /.well-known/trigguard-keys
         ▼
┌────────────────────┐
│    Key Cache       │
│  (local storage)   │
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│   Verifier SDK     │
│   (no network)     │
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│     Executor       │
│  (verifies grants) │
└────────────────────┘
```

After initial key fetch, **all verification is offline**:

1. No call to TrigGuard for signature verification
2. No call to TrigGuard for expiry checking
3. No call to TrigGuard for scope validation
4. No call to TrigGuard for constraint checking

This makes the system:
- **Fast** - No network latency for verification
- **Reliable** - Works even if TrigGuard is down
- **Scalable** - Executors can verify millions of grants

## Why This Is Protocol, Not Just Product

A **product** is something you use.
A **protocol** is something others can implement.

TrigGuard becomes a protocol because:

1. **Grant format is public** - Anyone can read and parse grants
2. **Verification is public** - Anyone can verify signatures
3. **Keys are discoverable** - Public key endpoint is standardized
4. **SDK is portable** - No TrigGuard runtime dependency

This means:
- Third-party executors can verify TrigGuard grants
- Third-party auditors can validate grant chains
- Third-party tools can parse grant data

## Future: Key Rotation with kid

The `kid` field enables key rotation:

```
Timeline:
─────────────────────────────────────────────────────────────►

Phase 1: tg-root-1 (active)
Grants signed with tg-root-1

Phase 2: tg-root-1 (active) + tg-root-2 (active)
Grants signed with either key

Phase 3: tg-root-1 (rotated) + tg-root-2 (active)
New grants signed with tg-root-2
Old grants still verifiable with tg-root-1

Phase 4: tg-root-2 (active) only
tg-root-1 removed after all grants expired
```

Key rotation is transparent to executors:
1. Fetch updated key set
2. Select key by kid in grant
3. Verify signature

## Security Boundaries

### What This Protocol Does

- ✅ Signature verification of grants
- ✅ Expiry enforcement
- ✅ Scope validation
- ✅ Constraint checking
- ✅ Audit trail generation

### What This Protocol Does NOT Do

- ❌ Make policy decisions
- ❌ Track grant usage
- ❌ Revoke individual grants
- ❌ Rate limit execution
- ❌ Store execution logs

These are executor responsibilities, not protocol responsibilities.

### Non-Goals

This protocol intentionally avoids:

1. **Online revocation** - Grants are short-lived (30s default), making revocation unnecessary
2. **Usage tracking** - Executors track their own usage
3. **Policy evaluation** - Policy belongs in TrigGuard, not executors
4. **Execution logging** - Executors own their audit logs

## Integration Checklist

For third-party executors:

- [ ] Fetch keys from `/.well-known/trigguard-keys`
- [ ] Cache key set locally
- [ ] Create `TrigGuardVerifierSDK` instance
- [ ] Load key set into SDK
- [ ] Create `ExecutorVerificationContract`
- [ ] Call `verify_before_execute()` before every action
- [ ] Log `decision.to_audit_dict()` for compliance
- [ ] Refresh keys periodically

## Example: Complete Flow

```python
import httpx
from trigguard.verification import TrigGuardVerifierSDK, PublicKeySet
from trigguard.executor import ExecutorVerificationContract

# 1. Fetch keys (once)
response = httpx.get("https://trigguard.example.com/.well-known/trigguard-keys")
key_set = PublicKeySet.from_dict(response.json())

# 2. Create SDK and contract
sdk = TrigGuardVerifierSDK()
sdk.load_key_set(key_set)
contract = ExecutorVerificationContract(sdk)

# 3. Receive grant from agent
grant = receive_grant_from_agent()

# 4. Verify before execution
decision = contract.verify_before_execute(
    grant,
    surface="SPEND",
    action="transfer_money",
    resource="account_123",
    execution_input={"amount": 50, "currency": "GBP"},
)

# 5. Execute or reject
if decision.allowed:
    transfer_money(...)
    audit_log(decision.to_audit_dict())
else:
    reject_request(decision.reason)
```

## Summary

The TrigGuard Verification Protocol provides:

1. **Public key discovery** via `/.well-known/trigguard-keys`
2. **Portable verification SDK** for offline grant verification
3. **Explicit executor contract** defining verification steps
4. **Audit-safe decision objects** for compliance logging

This makes TrigGuard the **authorization layer for AI actions** - not just a guardrail, but infrastructure that others can build on.
