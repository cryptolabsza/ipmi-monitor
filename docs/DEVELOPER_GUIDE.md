# IPMI Monitor - Developer Guide

This guide covers the development workflow, CI/CD pipeline, and release process for IPMI Monitor.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Branch Strategy](#branch-strategy)
3. [Development Workflow](#development-workflow)
4. [CI/CD Pipeline](#cicd-pipeline)
5. [Docker Image Tags](#docker-image-tags)
6. [Release Process](#release-process)
7. [Hotfix Process](#hotfix-process)
8. [Deployment Guide](#deployment-guide)
9. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Prerequisites

- Git
- Docker & Docker Compose
- Python 3.11+ (for local development)
- Access to GitHub repository

### Clone the Repository

```bash
git clone git@github.com:cryptolabsza/ipmi-monitor.git
cd ipmi-monitor
```

### Local Development Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run locally
python app.py
```

### Local Docker Build

```bash
# Build image locally
docker build -t ipmi-monitor:local .

# Run locally
docker run -p 5001:5001 -v ipmi-data:/app/data ipmi-monitor:local
```

---

## Branch Strategy

We use a simplified Git Flow with two main branches:

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   main ────●────────●────────●────────●────────●───────► STABLE    │
│            │        ↑        │        ↑        │                   │
│            │    (release)    │    (release)    │                   │
│            │        │        │        │        │                   │
│   develop ─●────●───●────●───●────●───●────●───●───────► DEVELOPMENT│
│            │    │        │        │        │                        │
│            ↓    ↓        ↓        ↓        ↓                        │
│          feat  feat    feat     feat     feat                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Branch Descriptions

| Branch | Purpose | Protected | Auto-Deploy |
|--------|---------|-----------|-------------|
| `main` | Production-ready stable code | ✅ Yes | `:main` tag |
| `develop` | Integration branch for features | ✅ Yes | `:dev` tag |
| `feature/*` | Individual feature work | ❌ No | PR builds only |
| `hotfix/*` | Emergency production fixes | ❌ No | - |

### Branch Protection Rules (Recommended)

For `main`:
- Require pull request reviews
- Require status checks to pass
- No direct pushes

For `develop`:
- Require status checks to pass
- Allow direct pushes for maintainers

---

## Development Workflow

### 1. Start a New Feature

```bash
# Always start from latest develop
git checkout develop
git pull origin develop

# Create feature branch
git checkout -b feature/my-awesome-feature
```

**Naming conventions:**
- `feature/add-gpu-monitoring` - New features
- `fix/resolve-memory-leak` - Bug fixes
- `refactor/cleanup-alerts` - Code improvements
- `docs/update-readme` - Documentation

### 2. Make Your Changes

```bash
# Make changes to code
# ...

# Stage and commit (use meaningful messages)
git add .
git commit -m "feat: Add GPU temperature monitoring

- Added GPU sensor collection via nvidia-smi
- Display GPU temps on dashboard
- Alert when GPU exceeds threshold

Closes #123"
```

**Commit Message Format:**
```
type: Short description (max 50 chars)

Longer description if needed. Explain what and why,
not how (the code shows how).

Closes #issue_number
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

### 3. Push and Create Pull Request

```bash
# Push to remote
git push origin feature/my-awesome-feature
```

Then on GitHub:
1. Click "Compare & pull request"
2. Set base branch to `develop`
3. Fill in PR template
4. Request review if needed

### 4. Code Review & CI

- CI will automatically run on your PR
- Address any review comments
- Once approved and CI passes, merge to `develop`

### 5. Delete Feature Branch

After merge:
```bash
git checkout develop
git pull origin develop
git branch -d feature/my-awesome-feature
```

---

## CI/CD Pipeline

### Pipeline Overview

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Push to    │────►│   GitHub     │────►│    Docker    │
│   Branch     │     │   Actions    │     │    Build     │
└──────────────┘     └──────────────┘     └──────────────┘
                            │                     │
                            ▼                     ▼
                     ┌──────────────┐     ┌──────────────┐
                     │    Tests     │     │  Push to     │
                     │   (future)   │     │    GHCR      │
                     └──────────────┘     └──────────────┘
```

### Trigger Events

| Event | What Happens |
|-------|--------------|
| Push to `develop` | Build `:dev`, `:develop` tags |
| Push to `main` | Build `:main` tag |
| Push tag `v*` | Build `:v1.x.x`, `:latest`, `:stable` |
| Pull Request | Build only (no push) |
| Manual dispatch | Build with optional custom tag |

### Pipeline File

Located at: `.github/workflows/docker-build.yml`

```yaml
# Key sections:

on:
  push:
    branches: [ main, master, develop ]
    tags: [ 'v*' ]
  pull_request:
    branches: [ main, master, develop ]

# Tags generated:
# - develop → :dev, :develop
# - main → :main
# - v1.6.0 → :v1.6.0, :1.6.0, :1.6, :latest, :stable
```

### Viewing Build Status

1. Go to repository on GitHub
2. Click "Actions" tab
3. Find your workflow run
4. Check logs for any errors

### Build Artifacts

All builds include:
- Git commit SHA
- Git branch name
- Build timestamp
- App version

View in running container:
```bash
docker exec ipmi-monitor env | grep -E "GIT_|BUILD_|APP_"
```

---

## Docker Image Tags

### Available Tags

| Tag | Source | Stability | Use Case |
|-----|--------|-----------|----------|
| `v1.6.0` | Git tag | ⭐ Stable | Production (pinned) |
| `latest` | Latest release tag | ⭐ Stable | Production (auto-update) |
| `stable` | Latest release tag | ⭐ Stable | Production alias |
| `main` | main branch | 🔶 Pre-release | Staging |
| `dev` | develop branch | ⚠️ Unstable | Development testing |
| `sha-abc123` | Any commit | 🔍 Debug | Troubleshooting |

### Pulling Images

```bash
# Production (recommended)
docker pull ghcr.io/cryptolabsza/ipmi-monitor:v1.6.0

# Latest stable
docker pull ghcr.io/cryptolabsza/ipmi-monitor:latest

# Development build
docker pull ghcr.io/cryptolabsza/ipmi-monitor:dev

# Specific commit
docker pull ghcr.io/cryptolabsza/ipmi-monitor:sha-306b173
```

---

## Release Process

### When to Release

- Feature complete and tested on `develop`
- All CI checks passing
- No known critical bugs
- Documentation updated

### Step-by-Step Release

#### 1. Prepare Release Notes

Create a list of changes since last release:
```bash
git log v1.5.0..develop --oneline
```

#### 2. Create Release PR

```bash
# Ensure develop is up to date
git checkout develop
git pull origin develop

# Create PR on GitHub: develop → main
# Title: "Release v1.6.0"
# Description: Include release notes
```

#### 3. Merge to Main

After PR approval:
- Squash and merge (or regular merge)
- Delete the PR branch if auto-created

#### 4. Create Release Tag

```bash
git checkout main
git pull origin main

# Create annotated tag
git tag -a v1.6.0 -m "Release v1.6.0

## New Features
- Alert resolution notifications
- GPU recovery agent
- Bulk credential management

## Improvements
- Dashboard performance
- Modal scrolling fix

## Bug Fixes
- Database migration issues
- Server display problems
"

# Push tag to trigger CI
git push origin v1.6.0
```

#### 5. Create GitHub Release

1. Go to: https://github.com/cryptolabsza/ipmi-monitor/releases
2. Click "Draft a new release"
3. Select tag: `v1.6.0`
4. Title: `v1.6.0`
5. Copy release notes from tag
6. Check "Set as the latest release"
7. Click "Publish release"

#### 6. Verify Deployment

```bash
# Check new image is available
docker pull ghcr.io/cryptolabsza/ipmi-monitor:v1.6.0

# Verify tags
docker images | grep ipmi-monitor
```

#### 7. Update Develop Branch

```bash
# Sync develop with main
git checkout develop
git merge main
git push origin develop
```

### Release Checklist

- [ ] All features tested on develop
- [ ] CI passing on develop
- [ ] Release notes prepared
- [ ] PR created: develop → main
- [ ] PR reviewed and approved
- [ ] PR merged
- [ ] Tag created and pushed
- [ ] GitHub release created
- [ ] Docker images built successfully
- [ ] Develop synced with main

---

## Hotfix Process

For critical production bugs that can't wait for normal release:

### 1. Create Hotfix Branch

```bash
git checkout main
git pull origin main
git checkout -b hotfix/critical-security-fix
```

### 2. Fix the Issue

```bash
# Make minimal fix
git add .
git commit -m "fix: Patch critical security vulnerability

- Sanitize user input in X endpoint
- Add rate limiting

CVE: CVE-2025-XXXX"
```

### 3. Create PR to Main

```bash
git push origin hotfix/critical-security-fix
# Create PR: hotfix/critical-security-fix → main
```

### 4. Merge and Tag

After approval:
```bash
git checkout main
git pull origin main

# Create patch version
git tag -a v1.6.1 -m "Hotfix: Critical security patch"
git push origin v1.6.1
```

### 5. Backport to Develop

```bash
git checkout develop
git merge main
git push origin develop
```

---

## Deployment Guide

### Production Deployment

```bash
# Using docker-compose.prod.yml
cd /path/to/deployment

# Update to new version
export IMAGE_TAG=v1.6.0

# Pull and restart
docker-compose -f docker-compose.prod.yml pull
docker-compose -f docker-compose.prod.yml up -d

# Verify
docker-compose -f docker-compose.prod.yml logs -f
```

### Development/Testing Deployment

```bash
# Using docker-compose.dev.yml
docker-compose -f docker-compose.dev.yml pull
docker-compose -f docker-compose.dev.yml up -d

# Access on port 5002 (to avoid prod conflicts)
open http://localhost:5002
```

### Rollback Procedure

If a release has issues:

```bash
# 1. Identify last good version
docker images | grep ipmi-monitor

# 2. Update docker-compose to previous version
# image: ghcr.io/cryptolabsza/ipmi-monitor:v1.5.0

# 3. Rollback
docker-compose down
docker-compose up -d

# 4. Verify
docker-compose logs -f
```

---

## Troubleshooting

### Build Failures

**Problem:** CI fails with "no space left on device"
```bash
# On self-hosted runner
docker system prune -af
docker volume prune -f
```

**Problem:** Image push fails with 403
- Check `GITHUB_TOKEN` permissions
- Verify package write access in workflow

### Runtime Issues

**Problem:** Container won't start
```bash
# Check logs
docker logs ipmi-monitor

# Common fixes
docker-compose down
docker volume rm ipmi-data  # ⚠️ Loses data
docker-compose up -d
```

**Problem:** Database migration errors
```bash
# Add missing columns manually
docker exec -it ipmi-monitor sqlite3 /app/data/ipmi_events.db
# Run ALTER TABLE statements
```

### Testing Dev Builds

```bash
# Run dev build alongside production
docker run -d \
  --name ipmi-monitor-test \
  -p 5002:5001 \
  -v ipmi-test-data:/app/data \
  ghcr.io/cryptolabsza/ipmi-monitor:dev

# Compare behavior
open http://localhost:5001  # prod
open http://localhost:5002  # dev
```

---

## Quick Reference

### Common Commands

```bash
# Switch to develop and update
git checkout develop && git pull

# Create feature branch
git checkout -b feature/name

# Push feature and create PR
git push -u origin feature/name

# Create release tag
git tag -a v1.x.x -m "Release v1.x.x" && git push origin v1.x.x

# Pull latest dev image
docker pull ghcr.io/cryptolabsza/ipmi-monitor:dev

# View container version
docker exec ipmi-monitor cat /app/VERSION
```

### Useful Links

- Repository: https://github.com/cryptolabsza/ipmi-monitor
- Actions: https://github.com/cryptolabsza/ipmi-monitor/actions
- Packages: https://github.com/cryptolabsza/ipmi-monitor/pkgs/container/ipmi-monitor
- Releases: https://github.com/cryptolabsza/ipmi-monitor/releases

---

## Questions?

If you have questions about the development process:
1. Check existing documentation
2. Search closed issues/PRs
3. Open a discussion on GitHub
4. Contact the maintainers

Happy coding! 🚀

