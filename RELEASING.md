# IPMI Monitor releases and installation channels

## Current installation recommendation

Recommend **GitHub main and Docker main, currently 1.4.2**. Verified on
7 November 2026: source `de79838a29fb60fb6b4c8ac537bcf1c46d7412fb` and
`ghcr.io/cryptolabsza/ipmi-monitor:main` are version 1.4.2. The same published
image is available as `:sha-de79838`, with digest
`sha256:4030892b06ea80f94d703066cb12774ed425e4e6c85c4e7e6c8da6b93d891625`.
The `main` alias advances when later main builds publish; verify the version
and commit again when preparing future release guidance.

The CLI and running dashboard are separate artifacts. Install the CLI from
GitHub `@main`, then explicitly select `ipmi_monitor.image_tag: main` in setup
configuration. See [README](README.md) for complete install commands and
[the user guide](docs/user-guide.md) for upgrades that preserve existing data.

| Channel | Recommendation |
| --- | --- |
| GitHub `@main` | Released CLI source; currently 1.4.2 |
| Docker `:main` | Released dashboard; currently 1.4.2 |
| Docker `:sha-de79838` | Source pin for verified 1.4.2 |
| Docker `:dev` / `:develop` | Explicit development testing only; may lag main |
| Docker `:latest` | Alias of the same verified main release image |
| Docker `:stable` | Legacy alias; not advanced by this publisher |
| PyPI `ipmi-monitor` | Check independently; observed 1.3.1, so use GitHub main |

## Why checking the destination matters

On 7 November 2026, Docker `:dev` still contained September's 1.1.9-dev and
`:latest` still contained 1.2.0. A green main workflow had correctly published
`:main` and `:sha-de79838`; it did not update those legacy aliases. The publisher
correction now advances the immutable source tag first, then `main`, then
`latest`, verifying the same artifact digest at each step. Development builds
never advance `latest`. Do not infer
publication from workflow success, a source tag, or a new CLI version alone.

## Updating an existing installation

Back up the existing database and configuration. Change only the IPMI Monitor
image in the existing Compose file to `ghcr.io/cryptolabsza/ipmi-monitor:main`
(or `:sha-de79838` for the verified pin), preserving volumes and settings.

```bash
sudo docker compose -f /etc/ipmi-monitor/docker-compose.yml pull ipmi-monitor
sudo docker compose -f /etc/ipmi-monitor/docker-compose.yml up -d ipmi-monitor
sudo docker exec ipmi-monitor python -c "import os; print(os.environ.get('APP_VERSION'), os.environ.get('GIT_COMMIT'))"
```

Use the actual Compose path for the deployment. Expect 1.4.2 and `de79838` for
this release. Do not remove data volumes or rerun fresh setup over an existing
installation. A rollback must use a previously verified image and compatible
data backup; an arbitrary old version tag is not rollback evidence.

## Source and release workflow

1. Develop in an isolated feature worktree branched from `dev`. Keep primary
   `dev` and `main` checkouts clean.
2. Run relevant tests and deterministic documentation/configuration checks.
   Preserve required CI, source review, traceability, and acceptance gates.
3. Push the feature branch and open a PR into `dev`. Merge only after the
   exact PR's required checks and review gates pass.
4. Prepare the reviewed `dev`-to-`main` release through a release branch/PR.
   Reconcile main's existing release metadata; do not downgrade its version.
5. For a runtime release, bump version only in the main release change, using
   Semantic Versioning and the repository's release policy. Feature branches
   and `dev` do not receive release version bumps. Documentation-only updates
   may retain the existing runtime version.
6. Tag the accepted runtime release and create its GitHub release using the
   normal reviewed publication route. Do not retag an existing version.
7. Verify the actual main Docker image's source commit, version, and digest.
   IPMI's publisher publishes a source SHA tag, then `main` and `latest`
   from the same verified digest. Version tags and `stable` must not be promised
   unless actually published.
8. Verify PyPI separately when its release workflow is authorized. A successful
   build can have a skipped publisher and does not prove a package upload.
9. Update all installation guides to the verified current main version and
   retain the source/image evidence. Do not claim customer deployment from
   source merge or image publication.

## CI boundaries

Builds and publishers use the reviewed disposable VM recipes and fixed
artifact identity checks. Preserve pinned workflows, selected runner groups,
least-privilege credentials, and required checks. Do not change shared pool
runtime or use host SSH, privileged fallbacks, credential copying, or skipped
checks to accelerate a release. Product release work must follow the policies
in [AGENTS.md](AGENTS.md).
