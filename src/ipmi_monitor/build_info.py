#!/usr/bin/env python3
"""Generate build_info.json with git commit and timestamp."""
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

def get_git_info():
    """Get git commit and branch info."""
    try:
        commit = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        branch = subprocess.check_output(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        return commit, branch
    except Exception:
        return 'unknown', 'unknown'

def main():
    """Generate build_info.json."""
    commit, branch = get_git_info()
    build_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    
    info = {
        'git_commit': commit,
        'git_branch': branch,
        'build_time': build_time,
    }
    
    # Write to package directory
    output_path = Path(__file__).parent / 'build_info.json'
    with open(output_path, 'w') as f:
        json.dump(info, f, indent=2)
    
    print(f"Generated {output_path}")
    print(f"  Branch: {branch}")
    print(f"  Commit: {commit[:7]}")
    print(f"  Time: {build_time}")

if __name__ == '__main__':
    main()
