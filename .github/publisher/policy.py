from verify_artifact import Policy

POLICY = Policy(
    repository='cryptolabsza/ipmi-monitor',
    repository_id=1109244855,
    workflow_path='.github/workflows/publish.yml',
    recipe_ref='cryptolabsza/ipmi-monitor/.github/workflows/ci-python-build-recipe.yml@a034e480f77032f3f9afdb079363dea23e48c87a',
    producer_job='cpu-build / build',
    group_id=11,
    build_label='ci-linux-cpu-v1-r1109244855',
    artifact_kind='pypi',
    artifact_stem='cpu-python',
)
PROJECT = 'ipmi-monitor'
PROJECT_FILE = 'pyproject.toml'
MIRROR_GITHUB = False
