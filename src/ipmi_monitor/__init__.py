"""
IPMI Monitor - Server Monitoring with AI-Powered Insights

A comprehensive IPMI/BMC monitoring solution for GPU datacenters and server rooms.
"""

__version__ = "1.1.5"
__author__ = "CryptoLabs"
__email__ = "info@cryptolabs.co.za"

# Build info - populated at build time or runtime
__git_commit__ = None
__git_branch__ = None
__build_time__ = None

def _load_build_info():
    """Load build info from _build_info.py if available."""
    global __git_commit__, __git_branch__, __build_time__
    try:
        from . import _build_info
        __git_commit__ = getattr(_build_info, 'GIT_COMMIT', None)
        __git_branch__ = getattr(_build_info, 'GIT_BRANCH', None)
        __build_time__ = getattr(_build_info, 'BUILD_TIME', None)
    except ImportError:
        pass

_load_build_info()


def get_version_info() -> str:
    """Get detailed version string with build info."""
    parts = [f"ipmi-monitor {__version__}"]
    
    if __git_branch__ or __git_commit__:
        build_parts = []
        if __git_branch__:
            build_parts.append(__git_branch__)
        if __git_commit__:
            build_parts.append(__git_commit__[:7])
        if build_parts:
            parts.append(f"({' '.join(build_parts)})")
    
    if __build_time__:
        parts.append(f"built {__build_time__}")
    
    return " ".join(parts)


def get_image_tag(dev: bool = False) -> str:
    """Return the Docker image tag to use.
    
    Always returns 'latest' (stable) unless --dev flag is explicitly passed.
    This prevents accidentally deploying dev images in production.
    
    Args:
        dev: If True, return 'dev' tag. Requires explicit --dev CLI flag.
    """
    if dev:
        return 'dev'
    return 'latest'
