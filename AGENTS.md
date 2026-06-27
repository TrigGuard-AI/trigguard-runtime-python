
## Agent skills (skills.sh)

Procedural skills live under `.agents/skills/` (`npx skills list`). **Read the relevant skill before improvising workflows.**

Domain focus: **Python runtime — reference alternate to Swift monorepo**. Full mapping: `.agents/skills/TRIGGUARD_SKILL_REGISTRY.md`.

Skills must not weaken fail-closed authorization, invent protocol semantics, or bypass TrigGuard enforcement surfaces.

## 🛠️ Procedural Memory & Skill Interception

Before executing any complex, multi-file refactoring, security audit, or integration task, you must check your local procedural library to see if a verified playbook exists for the job. Do not invent or hallucinate execution steps when standardized contracts are available on your shelf.

### 1. The Skill Discovery Rule

- At session start or right before analyzing a complex mission payload, read the local registry index at `.agents/skills/TRIGGUARD_SKILL_REGISTRY.md`.
- Match the mission requirements against the verified descriptions of your active skills.

### 2. Progressive Activation

- If a task matches an available skill (e.g., `spec-driven-development`, `verification-before-completion`, or `vibe-guard`), you must dynamically load and read the full `SKILL.md` instruction file inside that skill's subdirectory.
- Follow the documented patterns, scripts, and verification rules inside the skill completely rather than relying purely on baseline model memory.

### 3. Dynamic Discovery Gaps

- If a task is highly specialized and no matching local skill is found on your shelf, invoke the built-in asset helper:
  `npx skills list` or `npx skills find <keyword>`
- If an exact, high-leverage match exists within the `skills.sh` ecosystem that addresses a clear engineering or structural requirement, flag it to the user or execute a local project-level install using:
  `npx skills add <owner/repo> --skill <skill-name> -a cursor -y`
