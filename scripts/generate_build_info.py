#!/usr/bin/env python3
"""Generate build info file with git commit, branch, and timestamp."""

import subprocess
import os
from datetime import datetime
from pathlib import Path


def get_git_info():
    """Get git commit and branch info."""
    commit = None
    branch = None
    
    try:
        # Get commit hash
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            commit = result.stdout.strip()
        
        # Get branch name
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            branch = result.stdout.strip()
            # Handle detached HEAD (common in CI)
            if branch == "HEAD":
                # Try to get from environment (GitHub Actions)
                branch = os.environ.get("GITHUB_REF_NAME") or os.environ.get("GITHUB_HEAD_REF")
                if not branch:
                    # Try git describe
                    result = subprocess.run(
                        ["git", "describe", "--tags", "--always"],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        branch = result.stdout.strip()
    except Exception:
        pass
    
    return commit, branch


def generate_build_info():
    """Generate _build_info.py file."""
    commit, branch = get_git_info()
    build_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    
    # Find the target directory
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    target_dir = project_root / "src" / "ipmi_monitor"
    
    if not target_dir.exists():
        print(f"Warning: Target directory not found: {target_dir}")
        return
    
    build_info_file = target_dir / "_build_info.py"
    
    content = f'''"""Build information - auto-generated, do not edit."""

GIT_COMMIT = {repr(commit)}
GIT_BRANCH = {repr(branch)}
BUILD_TIME = {repr(build_time)}
'''
    
    build_info_file.write_text(content)
    print(f"Generated {build_info_file}")
    print(f"  Commit: {commit}")
    print(f"  Branch: {branch}")
    print(f"  Built: {build_time}")


if __name__ == "__main__":
    generate_build_info()
