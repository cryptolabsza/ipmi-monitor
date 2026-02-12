# Release Process for IPMI Monitor

This document describes how to manage releases to ensure production users are not affected by development work.

## Branch Strategy

```
main (stable)     ←── Only tested, production-ready code
  ↑
  │ (merge via PR after testing)
  │
develop (dev)     ←── Active development, new features
  ↑
  │ (merge via PR)
  │
feature/*         ←── Individual feature branches
```

## Docker Image Tags

| Tag | Description | Use Case |
|-----|-------------|----------|
| `v1.1.1` | Specific version | Production (recommended) |
| `latest` | Latest stable release | Production (auto-updates) |
| `stable` | Alias for latest release | Production |
| `dev` | Latest from develop branch | Testing new features |
| `main` | Latest from main branch | Staging |
| `sha-abc123` | Specific commit | Debugging |

## For Production Users

### Recommended: Pin to a specific version
```yaml
# docker-compose.yml
services:
  ipmi-monitor:
    image: ghcr.io/cryptolabsza/ipmi-monitor:v1.1.1
```

### Auto-update to latest stable
```yaml
services:
  ipmi-monitor:
    image: ghcr.io/cryptolabsza/ipmi-monitor:latest
```

### Upgrading
```bash
# Check current version
docker exec ipmi-monitor cat /app/VERSION 2>/dev/null || echo "Check dashboard header"

# Pull new version
docker pull ghcr.io/cryptolabsza/ipmi-monitor:v1.1.1

# Update and restart
docker-compose up -d
```

## For Developers

### Daily Development Workflow

1. **Create feature branch from develop**
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/my-new-feature
   ```

2. **Make changes and commit**
   ```bash
   git add .
   git commit -m "Add my new feature"
   ```

3. **Push and create PR to develop**
   ```bash
   git push origin feature/my-new-feature
   # Create PR on GitHub: feature/my-new-feature → develop
   ```

4. **After PR is merged, dev image is automatically built**
   - Image tag: `ghcr.io/cryptolabsza/ipmi-monitor:dev`

### Testing Dev Builds

```bash
# Pull latest dev build
docker pull ghcr.io/cryptolabsza/ipmi-monitor:dev

# Run on different port (5002)
docker-compose -f docker-compose.dev.yml up -d
```

## Creating a Release

### 1. Prepare Release

```bash
# Ensure develop is stable
git checkout develop
git pull origin develop

# Run tests locally
./run_tests.sh  # if exists

# Create PR: develop → main
# Title: "Release v1.1.1"
```

### 2. Merge to Main

After PR review and approval:
- Merge develop → main
- This triggers a build with tag `main`

### 3. Tag the Release

```bash
git checkout main
git pull origin main

# Create annotated tag
git tag -a v1.1.1 -m "Release v1.1.1

Features:
- Alert resolution notifications
- Bulk credential apply
- GPU recovery agent improvements

Fixes:
- Database migration for new alert fields
- Modal scrolling in settings
"

# Push tag
git push origin v1.1.1
```

### 4. Automatic Image Build

When the tag is pushed, GitHub Actions will:
1. Build the Docker image
2. Push with tags: `v1.1.1`, `1.1.1`, `1.1`, `latest`, `stable`

### 5. Create GitHub Release

1. Go to Releases page
2. Click "Draft a new release"
3. Select tag `v1.1.1`
4. Add release notes
5. Publish

## Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (v2.0.0): Breaking changes
- **MINOR** (v1.1.1): New features, backwards compatible
- **PATCH** (v1.1.2): Bug fixes only

## Hotfix Process

For critical production bugs:

```bash
# Create hotfix from main
git checkout main
git checkout -b hotfix/critical-fix

# Make fix
git commit -m "Fix critical bug"

# Create PR: hotfix/critical-fix → main
# After merge, tag immediately
git checkout main
git pull
git tag -a v1.1.2 -m "Hotfix: Critical bug fix"
git push origin v1.1.2

# Also merge fix back to develop
git checkout develop
git merge main
git push origin develop
```

## CI/CD Flow Diagram

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  feature/*   │────►│   develop    │────►│    main      │
│              │ PR  │              │ PR  │              │
└──────────────┘     └──────────────┘     └──────────────┘
                            │                    │
                            ▼                    ▼
                     ┌──────────────┐     ┌──────────────┐
                     │  :dev tag    │     │  :main tag   │
                     └──────────────┘     └──────────────┘
                                                │
                                                │ git tag v1.x.x
                                                ▼
                                         ┌──────────────┐
                                         │ :v1.x.x      │
                                         │ :latest      │
                                         │ :stable      │
                                         └──────────────┘
```

## Rollback Procedure

If a release has issues:

```bash
# Roll back to previous version
docker pull ghcr.io/cryptolabsza/ipmi-monitor:v1.1.0
docker-compose down
# Update docker-compose.yml to use v1.1.0
docker-compose up -d
```

