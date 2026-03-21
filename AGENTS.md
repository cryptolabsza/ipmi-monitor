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

## 4. Branching & Versioning Policy

All work **must** be committed on the `dev` branch. The `main` branch is the release branch.

### Workflow

1. **Develop on `dev`** — All feature work, bug fixes, and improvements are committed to `dev`.
   Do **not** commit directly to `main`.
2. **No version bumps on `dev`** — The version in `pyproject.toml` (or equivalent) stays
   unchanged while working on `dev`. Do not bump the version as part of a feature or fix commit.
3. **Bump version only when merging to `main`** — When `dev` is merged into `main` for a
   release, the version is bumped as part of that merge:
   - **Patch release** (bug fixes, small improvements): bump `+0.0.1` (e.g., `1.1.5` → `1.1.6`)
   - **Minor release** (new features, non-breaking changes): bump `+0.1.0` (e.g., `1.1.6` → `1.2.0`)
   - **Major release** (breaking changes, large rewrites): bump `+1.0.0` (e.g., `1.2.0` → `2.0.0`)
4. **Tag the release** — After merging to `main`, tag the commit with the version (e.g., `v1.1.6`).

### Rules

- Never commit directly to `main` — always merge from `dev`.
- Never bump the version on `dev` — the bump happens at merge-to-main time.
- Use [Semantic Versioning](https://semver.org/) (MAJOR.MINOR.PATCH).
- When in doubt about bump level, ask the user.

---

## 5. Android Version Code Monotonicity

Android **requires** `versionCode` to be strictly increasing across releases. A lower
`versionCode` than an already-installed APK causes "App not installed — package appears
to be invalid".

### Rules

- **Before modifying `versionCode`**, always check the **latest released value** in git
  history: `git log --all -1 -p -- android-app/app/build.gradle.kts | grep versionCode`.
- The new `versionCode` **must** be greater than the previously released value.
- **Never reset** `versionCode` (e.g., back to `1` or `2`). It must only go up.
- When bumping `versionName`, always bump `versionCode` by at least `+1` from the last
  released value.
- Include both `versionCode` and `versionName` changes in the same commit.

---

## 6. WordPress Shortcodes

When creating a new shortcode for the CryptoLabs AI Gateway plugin, **all four steps** are
required. Missing any step (especially step 3) will cause deployment failures.

### Checklist

1. **Create** the shortcode class:
   `plugin/cryptolabs-ai-gateway/includes/class-<name>-shortcode.php`
2. **Register** in `cryptolabs-ai-gateway.php` — add to the `$includes` array and call
   `::init()`.
3. **Deploy** — add `put includes/class-<name>-shortcode.php` to the SFTP batch in
   `.github/workflows/deploy-synchronized.yml`.
4. **Page** — create or document the WordPress page with the `[shortcode_tag]`.

### Rules

- Step 3 is the most commonly missed. The SFTP batch uses an **explicit file list** — files
  not listed are never uploaded to WordPress, even though they exist in Git.
- A missing file causes a PHP fatal error because `require_once` references a file that was
  never deployed.
- Before marking a shortcode task as complete, verify the filename appears in the `batch.txt`
  heredoc inside the `deploy-wordpress-plugin` job.
- See `.cursor/rules/wordpress-shortcodes.mdc` for the full checklist.

---

## 7. Self-Hosted Runner & CI/CD Standards

All CryptoLabs projects share self-hosted GitHub Actions runners. To prevent permission
failures, container breakage, and cross-project interference, **all workflows must follow
these standards**.

### Runner Configuration

- Runners execute as the `runner` user (uid 1001), which is a member of the `docker` group.
- Runner services are managed by systemd (`actions.runner.cryptolabsza.gpu-runner-*.service`).
- After any NVIDIA driver update or Docker daemon config change, **restart all runner services**
  via `systemctl restart actions.runner.cryptolabsza.gpu-runner-*.service`.

### Rules

#### Never use `sudo` in workflows

The `runner` user has limited sudoers entries. Using `sudo` causes intermittent failures
when the sudoers list doesn't cover the exact binary path (e.g., `sudo docker compose` vs
`sudo /usr/bin/docker-compose`).

- **Docker commands**: Use `docker` and `docker compose` directly — the runner is in the
  `docker` group.
- **Directory creation**: Ensure deployment directories (e.g., `/opt/<project>`) are owned
  by `runner:runner`. Create them once via root SSH, not in workflows.
- **Writing files**: Use `cat >` or `tee` without sudo. Ensure target files are writable by
  the runner user.

#### Deployment directory ownership

Every project that deploys to a self-hosted runner must have its deployment directory
pre-created and owned by `runner:runner`:

```bash
# One-time setup (run as root on the target server)
mkdir -p /opt/<project>
chown -R runner:runner /opt/<project>
```

If a directory is accidentally created as root, the next CI/CD run will fail with
"Permission denied". Fix with `chown -R runner:runner /opt/<project>`.

#### GPU / NVIDIA container runtime

- The NVIDIA container runtime config at `/etc/nvidia-container-runtime/config.toml` must
  use `mode = "auto"` (not `"cdi"`). CDI mode is incompatible with the
  `deploy.resources.reservations.devices` syntax used in docker-compose files.
- After changing nvidia-container-runtime config, run `systemctl restart docker` — then
  **immediately restart all compose stacks** because Docker restart stops all containers.
- GPU containers require the `deploy.resources.reservations.devices` block in docker-compose:
  ```yaml
  deploy:
    resources:
      reservations:
        devices:
          - driver: nvidia
            count: 1
            capabilities: [gpu]
  ```

#### Consistent runner labels

All self-hosted workflows must use the array format with an explicit OS label:

```yaml
runs-on: [self-hosted, linux]
```

Do not use bare `self-hosted` without the OS label.

#### Docker image builds (CI-only projects)

For projects that only build and push images (dc-overview, cryptolabs-proxy, ipmi-monitor):

- Prefer **GitHub Actions** (`docker/login-action`, `docker/build-push-action`,
  `docker/setup-buildx-action`) over raw Docker CLI commands.
- Use `GITHUB_TOKEN` or `CR_PAT` org secret for GHCR authentication.
- Tag strategy:
  - `dev` branch → `:dev` tag
  - `main` branch → `:latest` tag
  - Version tags (`v*`) → `:v1.2.3`, `:1.2.3`, `:1.2`, `:stable`
  - PRs → `:pr-<number>` (build only, no push)
- Clean up Docker config after builds: `if: always()` step to remove credentials.

#### Direct deployment projects (ipmi-monitor-ai and similar)

For projects that deploy directly on the runner host:

- Use `rsync` to sync files (exclude `.git`, `__pycache__`, `*.pyc`).
- Write `.env` files with `cat >` (no sudo). Set `chmod 600` on `.env` files.
- Always run `docker compose down` before `docker compose up -d`.
- Include a **health check** after deployment:
  ```bash
  sleep 10
  if curl -sf http://localhost:<port>/health; then
    echo "✅ Deployment successful!"
  else
    echo "❌ Health check failed"
    docker compose logs --tail 30
    exit 1
  fi
  ```
- On health check failure, show logs for debugging — do not silently fail.

#### Docker restart safety

Running `systemctl restart docker` stops **all** containers on the host. Before restarting
Docker:

1. Document all running compose stacks: `docker ps --format '{{.Names}}'`
2. After restart, bring all stacks back up in order:
   - Infrastructure first (postgres, redis)
   - Backend services (litellm, api-proxy)
   - Application services (ipmi-monitor-ai, sre-api, etc.)

### Checklist for new CI/CD workflows

- [ ] Uses `[self-hosted, linux]` runner labels
- [ ] No `sudo` in any step
- [ ] Deployment directory is `runner:runner` owned
- [ ] Secrets via `${{ secrets.* }}` only — never hardcoded
- [ ] `.env` files written with `chmod 600`
- [ ] Health check after deployment
- [ ] Docker image tag follows the standard scheme
- [ ] GPU projects use `deploy.resources.reservations.devices` syntax

---

## Summary

| Policy | One-Liner |
|--------|-----------|
| **TDD** | Write the test first, then make it pass, then clean up. |
| **Plan → Confirm → Implement** | Always present a plan and wait for approval. |
| **Org Secrets** | Never store credentials locally — use org secret management. |
| **Branching & Versioning** | Work on `dev`, bump version only when merging to `main`. |
| **Android versionCode** | Always check the last released `versionCode` and increment — never reset. |
| **WordPress Shortcodes** | Four steps: create class, register, add to SFTP batch, create WP page. |
| **CI/CD Runners** | No sudo, runner-owned dirs, health checks, `[self-hosted, linux]` labels. |

---

*Last updated: 2026-03-21*
