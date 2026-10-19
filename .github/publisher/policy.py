from verify_artifact import Policy

POLICY = Policy(
    repository='cryptolabsza/ipmi-monitor',
    repository_id=1109244855,
    workflow_path='.github/workflows/publish.yml',
    recipe_ref='cryptolabsza/ipmi-monitor/.github/workflows/ci-python-build-recipe.yml@65be759f062cb0b4fa0191379c1bbe2bbb8e0e87',
    producer_job='cpu-build / build',
    group_id=11,
    build_label='ci-linux-cpu-v1-r1109244855',
    artifact_kind='pypi',
    artifact_stem='cpu-python',
)
PROJECT = 'ipmi-monitor'
PROJECT_FILE = 'pyproject.toml'
MIRROR_GITHUB = False
