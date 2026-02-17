# AGENTS.md — CryptoLabs Development Policies

This file defines the mandatory policies that all AI coding agents (Cursor, Claude Code,
Copilot, etc.) **must** follow when working in this repository. These policies also apply
to human contributors.

---

## 1. Strict Test-Driven Development (TDD)

All code changes **must** follow the Red-Green-Refactor cycle:

1. **Red** — Write a failing test that describes the desired behaviour *before* writing
   any implementation code.
2. **Green** — Write the minimum amount of production code required to make the test pass.
3. **Refactor** — Clean up the code while keeping all tests green.

### Rules

- No production code may be written without a corresponding test.
- Tests must be committed alongside (or before) the implementation.
- Pull requests without adequate test coverage will be rejected.
- When fixing a bug, first write a test that reproduces the bug, then fix it.
- Prefer small, focused tests over large integration tests (unit → integration → e2e).

---

## 2. Plan First, Confirm Before Implementing

Agents **must not** jump straight into writing code. The required workflow is:

1. **Analyse** — Read and understand the relevant code, context, and requirements.
2. **Plan** — Produce a clear, numbered implementation plan that includes:
   - Files to be created or modified.
   - Tests to be written (TDD — tests come first).
   - Any dependencies or infrastructure changes.
   - Potential risks or trade-offs.
3. **Confirm** — Present the plan to the user and **wait for explicit approval** before
   making any changes.
4. **Implement** — Only after approval, proceed with the plan step by step.

### Rules

- Never skip the planning step, even for "small" changes.
- If the scope changes during implementation, stop and re-plan.
- When in doubt, ask — do not assume.

---

## 3. Organisation Secrets Over Local Credentials

All secrets, API keys, tokens, and credentials **must** be managed through organisation-level
secret stores. Locally stored credentials are **strictly prohibited**.

### Required Practices

- **GitHub Actions**: Use GitHub Organisation Secrets or Repository Secrets — never
  hard-code values in workflow files.
- **Environment variables**: Reference secrets from a secure vault (e.g., GitHub Secrets,
  1Password, HashiCorp Vault). Never commit `.env` files containing real credentials.
- **Docker / Compose**: Inject secrets at runtime via environment variables sourced from
  the org secret store. Never bake credentials into images.
- **Local development**: Use `.env.example` with placeholder values. Developers pull real
  values from the org secret manager.

### Rules

- `.env` files containing real secrets must be in `.gitignore` and **never** committed.
- No API keys, tokens, passwords, or private keys in source code — ever.
- Rotate any credential that has been accidentally committed, immediately.
- Prefer short-lived tokens and scoped permissions over long-lived master keys.
- All CI/CD pipelines must source secrets exclusively from org-level secret stores.

---

## Summary

| Policy | One-Liner |
|--------|-----------|
| **TDD** | Write the test first, then make it pass, then clean up. |
| **Plan → Confirm → Implement** | Always present a plan and wait for approval. |
| **Org Secrets** | Never store credentials locally — use org secret management. |

---

*Last updated: 2026-02-16*
