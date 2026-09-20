"""Release metadata stays consistent across build and runtime paths."""

from pathlib import Path
import tomllib


def test_runtime_version_matches_package_version():
    project = Path(__file__).parents[1] / "pyproject.toml"
    package_version = tomllib.loads(project.read_text())["project"]["version"]

    from ipmi_monitor import __version__

    assert __version__ == package_version
