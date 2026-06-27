# trigguard-system/trigguard-kernel — Project Skills Registry

Project-scoped [skills.sh](https://skills.sh/) packages under `.agents/skills/`.

## Progressive disclosure (read this index first)

1. **Index only** — at session start, read skill names and the mapping table below. Do **not** load every `SKILL.md`.
2. **Activate on match** — when a task matches a row, read `.agents/skills/<skill-name>/SKILL.md` in full before acting.
3. **Gap fill** — no local match: `npx skills list` or `npx skills find <keyword>`; install with `npx skills add <owner/repo> --skill <name> -a cursor -y`.

**Python runtime (`trigguard` on PyPI) — alternate implementation.**

| Skill | Use |
|-------|-----|
| `spec-driven-development` | Runtime behavior vs protocol contract |
| `vibe-guard` | PERMIT-gated execution paths |

## Verify

```bash
npx skills list
```

## QUANTA / TrigGuard overrides

1. **Protocol authority** — `trigguard-protocol` defines semantics; skills do not redefine the contract.
2. **Fail-closed** — PERMIT/DENY/SILENCE paths are normative; never bypass enforcement in examples or scripts.
3. **Review before trust** — check assessments at [skills.sh](https://skills.sh/) before `npx skills update`.
