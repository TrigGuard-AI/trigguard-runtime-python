# TrigGuard Execution Boundary

## NON-NEGOTIABLE RULE

**NO REAL-WORLD ACTION MAY EXECUTE WITHOUT PASSING THROUGH TRIGGUARD.**

If an action is **dangerous** or **irreversible**, it **MUST NOT** execute unless TrigGuard returns `PERMIT`.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Application / Agent                             │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      protected_* Functions                               │
│                   (core/protected_actions.py)                            │
│                                                                          │
│   protected_spend()          protected_code_exec()                       │
│   protected_data_export()    protected_delegation()                      │
│   protected_shell_command()  protected_identity_assertion()              │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        ExecutionAdapter                                  │
│                   (core/execution_adapter.py)                            │
│                                                                          │
│   • execute_if_permitted(surface, action, callable)                      │
│   • Only calls ExecutionGate (NO custom policy logic)                    │
│   • Enforces gate decision                                               │
│   • Attaches DecisionReceipt to all results                              │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        ExecutionGate                                     │
│                         (sdk/gate.py)                                    │
│                                                                          │
│   • Builds ExecutionRequest                                              │
│   • Collects Signals                                                     │
│   • Calls DecisionEngine                                                 │
│   • Returns GateResult                                                   │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       DecisionEngine                                     │
│                   (authority/decision_engine.py)                         │
│                                                                          │
│   • THE SOLE DETERMINISTIC DECISION AUTHORITY                            │
│   • Evaluates constraints                                                │
│   • Applies policies                                                     │
│   • Returns DecisionReceipt                                              │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
                    ▼                     ▼
            ┌───────────┐          ┌───────────┐
            │  PERMIT   │          │   DENY    │
            └─────┬─────┘          └─────┬─────┘
                  │                      │
                  ▼                      ▼
         Execute callable          ExecutionDenied
         Return result             (callable NEVER runs)
```

---

## Critical Invariants

### 1. No Bypass Execution

**Every dangerous action MUST go through ExecutionAdapter.**

```python
# ❌ FORBIDDEN - Direct execution
subprocess.run(["rm", "-rf", path])

# ✅ REQUIRED - Protected execution
from core.protected_actions import protected_shell_command

result = protected_shell_command(
    command=["rm", "-rf", path],
)
```

### 2. Adapter Only Enforces

**ExecutionAdapter may ONLY:**
- Call ExecutionGate
- Enforce the result
- Block execution when not permitted

**ExecutionAdapter may NEVER:**
- Invent policy logic
- Override decisions
- Skip evaluation

### 3. Denied Actions Never Execute

**If TrigGuard denies an action, the callable is NEVER called.**

```python
def dangerous_action():
    # This code NEVER runs if denied
    launch_nuclear_missiles()

# If denied, dangerous_action() is NEVER invoked
result = adapter.execute_if_permitted(
    surface="CODE_EXECUTION",
    action="launch",
    action_callable=dangerous_action,
)
```

### 4. Fail Closed

**Any error during evaluation results in DENY.**

```python
try:
    result = gate.evaluate(request)
except Exception:
    # DENY - fail closed
    raise FailClosedError(...)
```

### 5. Full Traceability

**Every permitted action includes DecisionReceipt.**

```python
result = adapter.execute_if_permitted(...)

# Audit trail
print(f"Receipt: {result.receipt_hash}")
print(f"Policy: {result.policy_version}")
print(f"Time: {result.timestamp}")
```

---

## Irreversible Surfaces

These surfaces represent actions that **cannot be undone**:

| Surface              | Description                     | Examples                        |
|----------------------|---------------------------------|---------------------------------|
| `SPEND`              | Financial transactions          | Payments, transfers, refunds    |
| `DATA_EXPORT`        | External data transmission      | API calls, file uploads         |
| `CODE_EXECUTION`     | Arbitrary code execution        | exec, subprocess, shell         |
| `DELEGATION`         | Capability granting             | Permissions, roles, API keys    |
| `IDENTITY_ASSERTION` | Acting as identity              | Signatures, claims, tokens      |
| `DATA_MUTATION`      | Irreversible data changes       | DELETE, TRUNCATE, bulk updates  |

---

## Protected Actions Reference

### SPEND Surface

```python
from core.protected_actions import protected_spend, protected_payment

# Financial transfer
result = protected_spend(
    amount=100.00,
    recipient="vendor@example.com",
    currency="USD",
    transfer_callable=lambda: stripe.transfer(100, "vendor"),
)

# Payment processing
result = protected_payment(
    payment_method="card_xxx",
    amount=50.00,
    description="Invoice #123",
    payment_callable=lambda: stripe.charge(50, card),
)
```

### DATA_EXPORT Surface

```python
from core.protected_actions import protected_data_export, protected_api_request

# External data export
result = protected_data_export(
    destination="https://partner.com/api",
    data_type="customer_records",
    export_callable=lambda: requests.post(url, json=data),
    data_summary="50 customer records",
)

# External API request
result = protected_api_request(
    method="POST",
    url="https://api.example.com/endpoint",
    request_callable=lambda: httpx.post(url, json=payload),
    contains_sensitive_data=True,
)
```

### CODE_EXECUTION Surface

```python
from core.protected_actions import protected_code_exec, protected_shell_command

# Code execution
result = protected_code_exec(
    code="print('hello')",
    language="python",
    exec_callable=lambda: exec("print('hello')"),
    trusted_source=False,
)

# Shell command
result = protected_shell_command(
    command=["git", "clone", repo_url],
    cwd="/tmp",
)
```

### DELEGATION Surface

```python
from core.protected_actions import protected_delegation, protected_permission_grant

# Capability delegation
result = protected_delegation(
    target="agent-123",
    capability="read:customer_data",
    delegation_callable=lambda: auth.grant(agent, capability),
    scope="workspace:proj-1",
)

# Permission grant
result = protected_permission_grant(
    principal="user@example.com",
    permission="admin",
    resource="project-xyz",
    grant_callable=lambda: rbac.grant(user, permission, resource),
)
```

### IDENTITY_ASSERTION Surface

```python
from core.protected_actions import protected_identity_assertion, protected_signature

# Identity assertion
result = protected_identity_assertion(
    identity="org:acme",
    assertion_type="claim",
    assertion_callable=lambda: claims.issue(org, claim),
    audience="partner-org",
)

# Digital signature
result = protected_signature(
    identity="org:acme",
    document_type="contract",
    signature_callable=lambda: crypto.sign(document, key),
    document_hash=hashlib.sha256(document).hexdigest(),
)
```

### DATA_MUTATION Surface

```python
from core.protected_actions import protected_data_mutation, protected_delete

# Bulk mutation
result = protected_data_mutation(
    resource="customers",
    mutation_type="bulk_delete",
    mutation_callable=lambda: db.execute(delete_query),
    affected_records=1000,
    reversible=False,
)

# Single deletion
result = protected_delete(
    resource="users",
    identifier="user-123",
    delete_callable=lambda: db.delete(user),
    cascade=True,
)
```

---

## Using the Decorator

For cleaner code, use the `@protected` decorator:

```python
from core.execution_adapter import protected

@protected(surface="SPEND", action="transfer")
def transfer_money(amount: float, recipient: str):
    return bank.transfer(amount, recipient)

# Calling transfer_money now goes through TrigGuard
result = transfer_money(100.0, "vendor@example.com")

# Result is ExecutionResult, not raw return value
print(f"Transfer: {result.result}")
print(f"Receipt: {result.receipt_hash}")
```

---

## Error Handling

### ExecutionDenied

Raised when TrigGuard denies execution:

```python
from core.execution_adapter import ExecutionDenied

try:
    result = protected_spend(
        amount=1_000_000,
        recipient="unknown",
        transfer_callable=lambda: bank.transfer(1_000_000),
    )
except ExecutionDenied as e:
    print(f"Denied: {e.reason}")
    print(f"Surface: {e.surface}")
    print(f"Receipt: {e.receipt.receipt_hash}")
```

### FailClosedError

Raised when evaluation fails (system error):

```python
from core.execution_adapter import FailClosedError

try:
    result = adapter.execute_if_permitted(...)
except FailClosedError as e:
    print(f"System error: {e.original_error}")
    # The action was NOT executed
```

---

## Static Analysis

### Bypass Pattern Detection

Run static scans on every commit:

```bash
python -m pytest tests/test_no_bypass_patterns.py -v
```

Or run directly:

```bash
python tests/test_no_bypass_patterns.py
```

### Detected Patterns

| Pattern              | Severity | Use Instead                    |
|----------------------|----------|--------------------------------|
| `subprocess.run`     | CRITICAL | `protected_shell_command()`    |
| `subprocess.Popen`   | CRITICAL | `protected_shell_command()`    |
| `os.system`          | CRITICAL | `protected_shell_command()`    |
| `exec()`             | CRITICAL | `protected_code_exec()`        |
| `eval()`             | CRITICAL | `protected_code_exec()`        |
| `requests.post`      | HIGH     | `protected_api_request()`      |
| `requests.put`       | HIGH     | `protected_api_request()`      |

---

## Testing

### Execution Boundary Tests

```bash
python -m pytest tests/test_execution_boundary.py -v
```

These tests verify:
- No action executes without ExecutionAdapter
- ExecutionAdapter only calls ExecutionGate
- Denied actions never call callable
- PERMIT decisions attach DecisionReceipt
- Fail-closed on errors

---

## Integration Checklist

When adding new dangerous functionality:

1. [ ] Identify the execution surface (SPEND, CODE_EXEC, etc.)
2. [ ] Add protected_* function to `core/protected_actions.py`
3. [ ] Update bypass pattern detection if new patterns needed
4. [ ] Add tests to `tests/test_execution_boundary.py`
5. [ ] Update this documentation

---

## Contact

For security concerns, see [SECURITY.md](../SECURITY.md).
