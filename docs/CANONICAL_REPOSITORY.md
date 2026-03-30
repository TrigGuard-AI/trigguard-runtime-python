# Canonical repository (Python runtime)

## GitHub (public ecosystem)

**Repository:** [TrigGuard-AI/trigguard-runtime-python](https://github.com/TrigGuard-AI/trigguard-runtime-python)

This is the **Python runtime implementation** of the TrigGuard protocol: evaluation, gates, and HTTP surfaces as implemented here. It is an **alternate runtime**; the **reference** product/runtime implementation remains the **[TrigGuard](https://github.com/TrigGuard-AI/TrigGuard)** monorepo.

**Protocol semantics** are defined only in **[trigguard-protocol](https://github.com/TrigGuard-AI/trigguard-protocol)** — this repo implements them; it does not redefine the contract.

## PyPI package name

The installable package remains **`trigguard`** (see `pyproject.toml`). The GitHub repository name **`trigguard-runtime-python`** describes **role** (runtime + language), not the PyPI distribution name.

## Legacy GitLab remote

Some clones may still use:

- `https://gitlab.com/TrigGuardAI/trigguard-kernel.git`

That remote is **legacy**. **GitHub is the only canonical** public home for this codebase.

### Option A (recommended): archive or retire the GitLab project

Mark the GitLab project **archived** (read-only) and rely on the README banner (and this doc) so GitLab is never mistaken for a second source of truth.

### Option B: read-only mirror from GitHub

If you need GitLab for internal CI or compliance, configure **pull mirroring** in GitLab (**Settings → Repository → Mirroring repositories**) so **GitHub → GitLab** is automatic. Do **not** merge competing changes on GitLab `main`; treat GitLab as a passive mirror.

### What not to do

- Do **not** unprotect GitLab `main` just to “sync faster” — that weakens governance.
- Do **not** describe GitLab as equally canonical in docs or onboarding.

New work should **clone from GitHub** and open issues/PRs there.

## Rename (optional)

If you have a local folder named `trigguard-kernel`, you can rename it to `trigguard-runtime-python` for clarity; it is not required for the package to work.
