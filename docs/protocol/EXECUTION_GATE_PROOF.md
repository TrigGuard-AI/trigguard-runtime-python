# Execution Gate Proof

## 1. What Execution Gate Proof is
Execution Gate Proof is a signed, portable artifact that proves a request was authorized by TrigGuard before execution. It is designed for downstream verification and audit, not for making authorization decisions.

## 2. Difference between DecisionReceipt and ExecutionGateProof
- **DecisionReceipt**: The canonical artifact of the authorization decision, internal to TrigGuard.
- **ExecutionGateProof**: A portable, signed proof that a request passed through TrigGuard, suitable for transport (e.g., via HTTP headers).

## 3. Why this exists
To allow APIs, runtimes, and services to verify that a request was authorized by TrigGuard before execution, without delegating decision authority.

## 4. Proof object schema
```
@dataclass(frozen=True)
class ExecutionGateProof:
    proof_id: str
    protocol: str
    version: str
    decision: str
    surface_id: str
    receipt_hash: str
    decision_hash: Optional[str]
    surface_hash: Optional[str]
    runtime_version: str
    issued_at: str
    signature_alg: str
    signature: str
```

## 5. Canonical serialization
- Deterministic, sorted, compact JSON
- Signature is over canonical payload (excluding signature field)

## 6. HTTP header transport
- Main header: `X-TrigGuard-Proof`
- Additional: `X-TrigGuard-Receipt-Hash`, `X-TrigGuard-Surface`, `X-TrigGuard-Decision`
- Header is a URL-safe base64 of canonical JSON
- Header transport is for convenience only; canonical proof object is the source of truth

## 7. Verification flow
1. Decode header to canonical JSON
2. Reconstruct proof object
3. Verify required fields and protocol
4. Verify signature using trusted key
5. Check version and receipt_hash
6. Validate decision as artifact (not for authorization)

## 8. Security boundaries
- The kernel remains the sole decision authority
- Proof is evidence only, not policy
- No runtime/service/decorator may decide PERMIT/DENY
- Proofs are deterministic, signed, and replay-safe
- Header support is transport convenience only

## 9. Example request/response headers
```
X-TrigGuard-Proof: eyJwcm9vZl9pZCI6ImlkMSIsInByb3RvY29sIjoidHJpZ3... (base64)
X-TrigGuard-Receipt-Hash: abc123
X-TrigGuard-Surface: trigguard.spend.transfer
X-TrigGuard-Decision: PERMIT
```

---

- receipt = decision artifact
- proof = transportable evidence that authorization happened before execution
