from verify_artifact import Policy
from transport import main
POLICY=Policy(repository='cryptolabsza/ipmi-monitor',repository_id=1109244855,workflow_path='.github/workflows/docker-build.yml',recipe_ref='cryptolabsza/ipmi-monitor/.github/workflows/ci-image-build-recipe.yml@a034e480f77032f3f9afdb079363dea23e48c87a',producer_job='build / build',group_id=11,build_label='ci-linux-cpu-v1-r1109244855',artifact_kind='oci',artifact_stem='cpu-image',transport_schema=2)
IMAGES=['ipmi-monitor']
if __name__=='__main__':raise SystemExit(main(POLICY,IMAGES))
