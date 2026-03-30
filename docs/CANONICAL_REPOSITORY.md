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

That remote is **legacy**. New work should **clone from GitHub** and push to GitHub; keep GitLab only if you need a mirror for CI/CD until you migrate pipelines.

## Rename (optional)

If you have a local folder named `trigguard-kernel`, you can rename it to `trigguard-runtime-python` for clarity; it is not required for the package to work.
