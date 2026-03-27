# TrigGuard Threat Model

> Version: 1.0.0  
> Last Updated: 2026-03-27  
> Status: STABLE

---

## 1. System Purpose

**TrigGuard is a deterministic pre-execution authorization layer for automated systems.**

Its purpose is to evaluate whether an automated action should be permitted before execution, using normalized signals, constraints, and policy.

TrigGuard is **not**:
- A prompt moderation tool
- A chatbot safety filter
- A behavior monitor

TrigGuard **is**:
- The execution gate
- The final authority before irreversible action
- A deterministic decision boundary

---

## 2. Protected Assets

TrigGuard exists to protect these assets from unauthorized access or manipulation:

| Asset | Description |
|-------|-------------|
| **Execution Authority** | The ability to trigger automated actions |
| **Spend Authority** | Financial transactions, payments, purchases |
| **Data Export Capability** | Ability to send data outside the system boundary |
| **Identity Assertion** | Acting as or on behalf of a specific identity |
| **Delegation Authority** | Granting permissions or access to other principals |
| **Code Execution** | Running arbitrary code or scripts |
| **API Privileges** | Access to internal and external APIs |
| **Retrieval Context** | RAG documents, knowledge bases, sensitive context |
| **System Instructions** | System prompts, control instructions, configuration |
| **Audit Integrity** | Decision receipts, logs, forensic trail |

---

## 3. Security Boundary

```
UNTRUSTED INPUT
       ↓
Signal Producers (Detectors)
       ↓
SignalFrame (normalized signals)
       ↓
ConstraintEvaluator
       ↓
DecisionEngine ← SOLE AUTHORITY
       ↓
PERMIT / DENY / SILENCE
       ↓
Execution Adapter
       ↓
PROTECTED ACTION
```

### Boundary Rules

1. **Detectors are advisory signal producers only.**  
   They cannot authorize or deny execution.

2. **DecisionEngine is the sole authority.**  
   Only DecisionEngine can emit PERMIT / DENY / SILENCE.

3. **SignalFrame is the interface.**  
   All detector outputs are normalized into signals before evaluation.

4. **Fail closed by default.**  
   Unknown states, missing signals, or ambiguity result in DENY.

---

## 4. Attacker Types

### 4.1 Curious User
- **Goal**: Extract more than intended
- **Methods**: System prompt probing, capability testing, hidden tool discovery
- **Risk Level**: Low-Medium

### 4.2 Malicious End User
- **Goal**: Break safety boundaries, extract data, abuse tools
- **Methods**: Jailbreaks, prompt injection, role override, data exfiltration
- **Risk Level**: Medium-High

### 4.3 Automated Exploit Bot
- **Goal**: Systematic vulnerability discovery
- **Methods**: Repeated probing, mutation fuzzing, escalation ladders
- **Risk Level**: High

### 4.4 Compromised Agent / Workflow
- **Goal**: Execute outside intended bounds
- **Methods**: Goal hijacking, plan poisoning, authority escalation
- **Risk Level**: Critical

### 4.5 Insider / Misconfigured Operator
- **Goal**: (Intentional or accidental) excessive permissions
- **Methods**: Unsafe policy configuration, permission over-granting
- **Risk Level**: Critical

---

## 5. Execution Surfaces

Execution surfaces are classified by risk tier. Higher tiers require stricter thresholds.

### Tier 1: Irreversible (Risk Threshold: 0.3)

| Surface | Description |
|---------|-------------|
| `SPEND` | Financial transactions |
| `EXPORT` | Data leaving the system |
| `DELEGATION` | Authority transfer |
| `IDENTITY_ASSERTION` | Acting as a specific identity |
| `CODE_EXECUTION` | Running arbitrary code |
| `DATA_MUTATION` | Modifying persistent data |

### Tier 2: Medium Consequence (Risk Threshold: 0.6)

| Surface | Description |
|---------|-------------|
| `EXTERNAL_API` | Calls to external services |
| `INTERNAL_API` | Internal service calls |
| `TOOL_INVOCATION` | Calling registered tools |

### Tier 3: Low Consequence (Risk Threshold: 0.8)

| Surface | Description |
|---------|-------------|
| `INFERENCE` | Model inference only |
| `RETRIEVAL` | RAG / knowledge retrieval |
| `GENERATION` | Text/content generation |

### Surface Rules

- Higher-risk surfaces require stricter thresholds
- Higher-risk surfaces require stronger signals
- Irreversible surfaces fail closed on ambiguity
- Unknown surfaces are treated as Tier 1

---

## 6. Attack Classes

### A. Prompt Manipulation

**Goal**: Alter system behavior before execution.

| Attack | Description | Signal |
|--------|-------------|--------|
| Prompt Injection | Override intended instructions | `prompt_override` |
| Role Override | Change AI persona/role | `role_escalation` |
| Instruction Hijack | Replace system instructions | `instruction_rewrite` |
| Persona Manipulation | Gradually shift AI identity | `identity_confusion` |
| Context Poisoning | Build false assumptions | `context_poisoning` |

### B. Safety Bypass

**Goal**: Weaken or bypass safeguards.

| Attack | Description | Signal |
|--------|-------------|--------|
| Jailbreak | Break out of safety constraints | `jailbreak_attempt` |
| Refusal Bypass | Circumvent content refusal | `safety_bypass` |
| Adversarial Phrasing | Obfuscate malicious intent | `adversarial_input` |
| Policy Evasion | Exploit policy gaps | `policy_evasion` |

### C. Data Extraction

**Goal**: Obtain protected data or instructions.

| Attack | Description | Signal |
|--------|-------------|--------|
| System Prompt Probing | Extract system instructions | `system_prompt_access` |
| CoT Extraction | Extract reasoning steps | `cot_extraction` |
| Secret Retrieval | Access credentials/keys | `secret_access_attempt` |
| RAG Document Leak | Extract retrieval context | `rag_leak_attempt` |
| Context Window Fishing | Probe conversation history | `context_extraction` |

### D. Tool Exploitation

**Goal**: Misuse authorized tools or function calls.

| Attack | Description | Signal |
|--------|-------------|--------|
| Tool Injection | Inject tool calls via prompt | `tool_call_injection` |
| Function Call Injection | Manipulate function parameters | `function_call_injection` |
| Privilege Escalation | Access higher-privilege tools | `tool_escalation` |
| Parameter Smuggling | Hide malicious parameters | `parameter_smuggling` |
| Dangerous Sequencing | Chain tools dangerously | `tool_sequence_abuse` |

### E. Execution Abuse

**Goal**: Trigger actions that should not happen.

| Attack | Description | Signal |
|--------|-------------|--------|
| Unauthorized Spend | Trigger payments without auth | `unauthorized_spend` |
| Unauthorized Export | Exfiltrate data | `unauthorized_export` |
| Unauthorized Execution | Run code without auth | `unauthorized_execution` |
| Identity Spoofing | Act as another principal | `identity_spoofing` |
| Delegation Abuse | Grant unauthorized access | `delegation_abuse` |

### F. Agent Manipulation

**Goal**: Steer agent goals or action plans over time.

| Attack | Description | Signal |
|--------|-------------|--------|
| Goal Hijack | Redirect agent objective | `goal_hijack` |
| Multi-step Escalation | Gradual permission creep | `multi_step_escalation` |
| Plan Poisoning | Corrupt agent action plans | `plan_poisoning` |
| State Poisoning | Corrupt agent memory/state | `state_poisoning` |

---

## 7. Threat-to-Signal Mapping

Every threat maps to a normalized signal. Detectors produce signals; DecisionEngine evaluates them.

| Threat | Signal Type | Severity |
|--------|-------------|----------|
| Prompt injection | `prompt_override` | HIGH |
| Instruction hijack | `instruction_rewrite` | HIGH |
| Role override | `role_escalation` | HIGH |
| Jailbreak | `jailbreak_attempt` | CRITICAL |
| System prompt probing | `system_prompt_access` | HIGH |
| RAG leakage | `rag_leak_attempt` | HIGH |
| CoT extraction | `cot_extraction` | MEDIUM |
| Tool injection | `tool_call_injection` | HIGH |
| Function injection | `function_call_injection` | HIGH |
| Privilege escalation | `tool_escalation` | CRITICAL |
| Model enumeration | `model_enumeration` | MEDIUM |
| Goal hijack | `goal_hijack` | CRITICAL |

### Signal Flow

```
Threat detected by detector
         ↓
Detector emits raw finding
         ↓
Finding normalized to Signal
         ↓
Signals aggregated into SignalFrame
         ↓
ConstraintEvaluator checks constraints
         ↓
DecisionEngine makes deterministic decision
         ↓
DecisionReceipt produced
```

---

## 8. Failure Modes

TrigGuard fails closed. The following conditions result in DENY:

| Condition | Decision | Reason |
|-----------|----------|--------|
| Unknown surface | DENY | `surface_not_allowed` |
| Missing required signal | DENY | `missing_required_signal` |
| Risk threshold exceeded | DENY | `risk_threshold_exceeded` |
| Forbidden signal present | DENY | `forbidden_signal` |
| Detector disagreement on irreversible | DENY | `fail_closed` |
| Unsupported policy branch | DENY | `policy_denial` |
| Critical constraint violation | DENY | `constraint_violation` |
| Probing attack detected | SILENCE | (no response) |

### Fail-Closed Doctrine

1. **Uncertain? DENY.**
2. **Unknown? DENY.**
3. **Ambiguous on irreversible? DENY.**
4. **Probing attack? SILENCE.**

---

## 9. Security Guarantees

TrigGuard provides these guarantees:

| Guarantee | Description |
|-----------|-------------|
| **Determinism** | Same input always yields same decision |
| **Sole Authority** | Only DecisionEngine can emit PERMIT/DENY/SILENCE |
| **Signal Isolation** | Detectors cannot authorize execution |
| **Fail Closed** | Unknown or unsupported states result in DENY |
| **Tiered Risk** | Irreversible surfaces are handled more strictly |
| **Audit Trail** | Every decision produces an immutable DecisionReceipt |
| **No Information Leak** | Probing attacks receive SILENCE, not errors |

---

## 10. Non-Goals

TrigGuard explicitly does **not**:

| Non-Goal | Explanation |
|----------|-------------|
| Guarantee model truthfulness | We authorize execution, not verify facts |
| Replace application logic | Business rules belong in the application |
| Provide forensics as primary function | We produce receipts; forensics is downstream |
| Act as chatbot moderation | We are not a content filter |
| Infer emotions/intentions | We evaluate signals, not psychology |
| Predict future behavior | We authorize the current request only |

---

## Appendix A: Signal Severity Levels

| Level | Description | Impact |
|-------|-------------|--------|
| CRITICAL | Immediate threat, likely attack | Automatic DENY |
| HIGH | Serious risk, warrants blocking | DENY on irreversible |
| MEDIUM | Elevated risk, may require review | FLAG or threshold check |
| LOW | Minor concern | Usually permitted |
| INFO | Observational only | No impact on decision |

---

## Appendix B: Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-03-27 | Initial threat model |

---

*This document is the authoritative threat model for TrigGuard kernel. All detector design, constraint evaluation, and policy decisions must derive from this model.*
