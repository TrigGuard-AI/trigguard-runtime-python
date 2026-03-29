# TrigGuard Policy Discovery Endpoint

## Purpose
Enable automatic detection of TrigGuard execution governance by agents, frameworks, and external systems. This endpoint provides protocol-level metadata for integration and compliance.

## Endpoint
```
GET /.well-known/trigguard-policy
```

## Example Request
```
GET /.well-known/trigguard-policy
```

## Example Response
```json
{
  "protocol": "trigguard",
  "version": "0.2.1",
  "decision_endpoint": "/v1/decide",
  "receipt_endpoint": "/v1/receipts",
  "surface_registry": "/.well-known/trigguard-surfaces",
  "attestation_supported": true,
  "signature_alg": "ed25519"
}
```

## Security Model
- This endpoint is **read-only** and provides metadata only.
- It does **not** introduce any decision authority or modify policy behavior.
- The SafetyEngine remains the sole PERMIT/DENY authority.

## Fields
- `protocol`: Always "trigguard".
- `version`: TrigGuard runtime version.
- `decision_endpoint`: Path for decision requests.
- `receipt_endpoint`: Path for execution receipts.
- `surface_registry`: Path for surface registry discovery.
- `attestation_supported`: Whether attestation is supported.
- `signature_alg`: Signature algorithm used (e.g., "ed25519").

## Usage
External agents and frameworks can use this endpoint to:
- Detect TrigGuard protocol presence
- Route execution through the decision engine
- Integrate with surface registry and attestation features

## Protocol Integration Flow
1. Agent startup
2. Check `/.well-known/trigguard-policy`
3. If detected, route execution through TrigGuard

## Changelog
- v0.2.1: Initial protocol discovery endpoint
