from verify_artifact import Policy
from transport import main
POLICY=Policy(repository='cryptolabsza/ipmi-monitor',repository_id=1109244855,workflow_path='.github/workflows/docker-build.yml',recipe_ref='cryptolabsza/ipmi-monitor/.github/workflows/ci-image-build-recipe.yml@7a8e38d6a61a10337e4f71f6219f67d03f9b2aa1',producer_job='build / build',group_id=11,build_label='ci-linux-cpu-v1-r1109244855',artifact_kind='oci',artifact_stem='cpu-image',transport_schema=2)
IMAGES=['ipmi-monitor']
if __name__=='__main__':raise SystemExit(main(POLICY,IMAGES))
