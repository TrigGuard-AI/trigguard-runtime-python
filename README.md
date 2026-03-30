# TrigGuard (Python runtime)

**Canonical repository (GitHub):**  
**[github.com/TrigGuard-AI/trigguard-runtime-python](https://github.com/TrigGuard-AI/trigguard-runtime-python)

This repository is the **Python runtime** for the TrigGuard protocol (gates, policy evaluation, HTTP services). **Normative protocol semantics** live in [`trigguard-protocol`](https://github.com/TrigGuard-AI/trigguard-protocol) only. The **reference** runtime implementation is the [`TrigGuard`](https://github.com/TrigGuard-AI/TrigGuard) monorepo — this Python package is an **alternate** runtime implementation.

See [`docs/CANONICAL_REPOSITORY.md`](docs/CANONICAL_REPOSITORY.md) for GitLab legacy remote and naming notes.

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

## Badges
On some READMEs, you may see small images that convey metadata, such as whether or not all the tests are passing for the project. You can use Shields to add some to your README. Many services also have instructions for adding a badge.

## Visuals
Depending on what you are making, it can be a good idea to include screenshots or even a video (you'll frequently see GIFs rather than actual videos). Tools like ttygif can help, but check out Asciinema for a more sophisticated method.

## Installation
Within a particular ecosystem, there may be a common way of installing things, such as using Yarn, NuGet, or Homebrew. However, consider the possibility that whoever is reading your README is a novice and would like more guidance. Listing specific steps helps remove ambiguity and gets people to using your project as quickly as possible. If it only runs in a specific context like a particular programming language version or operating system or has dependencies that have to be installed manually, also add a Requirements subsection.

## Usage
Use examples liberally, and show the expected output if you can. It's helpful to have inline the smallest example of usage that you can demonstrate, while providing links to more sophisticated examples if they are too long to reasonably include in the README.

## Support
Tell people where they can go to for help. It can be any combination of an issue tracker, a chat room, an email address, etc.

## Roadmap
If you have ideas for releases in the future, it is a good idea to list them in the README.

## Contributing
State if you are open to contributions and what your requirements are for accepting them.

For people who want to make changes to your project, it's helpful to have some documentation on how to get started. Perhaps there is a script that they should run or some environment variables that they need to set. Make these steps explicit. These instructions could also be useful to your future self.

You can also document commands to lint the code or run tests. These steps help to ensure high code quality and reduce the likelihood that the changes inadvertently break something. Having instructions for running tests is especially helpful if it requires external setup, such as starting a Selenium server for testing in a browser.

## Authors and acknowledgment
Show your appreciation to those who have contributed to the project.

## License
For open source projects, say how it is licensed.

## Project status
If you have run out of energy or time for your project, put a note at the top of the README saying that development has slowed down or stopped completely. Someone may choose to fork your project or volunteer to step in as a maintainer or owner, allowing your project to keep going. You can also make an explicit request for maintainers.
