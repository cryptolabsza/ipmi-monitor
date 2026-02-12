"""Setup script that generates build info before building."""

import subprocess
import sys
from pathlib import Path
from datetime import datetime
import os


def generate_build_info():
    """Generate _build_info.py with git and timestamp info."""
    commit = None
    branch = None
    
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            commit = result.stdout.strip()
        
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            branch = result.stdout.strip()
            if branch == "HEAD":
                branch = os.environ.get("GITHUB_REF_NAME") or os.environ.get("GITHUB_HEAD_REF") or "detached"
    except Exception:
        pass
    
    # For release builds (tag like v1.1.2), map to 'main' since releases come from main
    if branch and branch.startswith('v') and '.' in branch:
        branch = 'main'
    
    # If still no branch info, default to 'main' for PyPI releases
    if not branch or branch == 'detached':
        branch = 'main'
    
    build_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    
    target_dir = Path(__file__).parent / "src" / "ipmi_monitor"
    build_info_file = target_dir / "_build_info.py"
    
    content = f'''"""Build information - auto-generated, do not edit."""

GIT_COMMIT = {repr(commit)}
GIT_BRANCH = {repr(branch)}
BUILD_TIME = {repr(build_time)}
'''
    
    build_info_file.write_text(content)
    print(f"Generated build info: branch={branch}, commit={commit[:7] if commit else None}")


# Generate build info before setuptools runs
generate_build_info()

# Let setuptools handle the rest via pyproject.toml
from setuptools import setup
setup()
