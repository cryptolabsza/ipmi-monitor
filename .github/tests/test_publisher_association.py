"""Recorded protected push PR associations carry no publication event authority."""
import copy,json,sys
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'.github/image-publisher'))
import verify_artifact as v
FIXTURE=json.loads((ROOT/'.github/tests/fixtures/tts-push-pr-association.json').read_text())
RUN=39189170762;ART=12160040270;BASE='/repos/cryptolabsza/Custom-TTS';RUNPATH=BASE+'/actions/runs/'+str(RUN)
POLICY=v.Policy(repository='cryptolabsza/Custom-TTS',repository_id=1109245105,workflow_path='.github/workflows/build-deploy.yml',recipe_ref='cryptolabsza/Custom-TTS/.github/workflows/ci-build-recipe.yml@7adebbd55b2c568f649d0785aec70917eb2a5a16',producer_job='build / build',group_id=10,build_label='ci-linux-cpu-v1-r1109245105',artifact_kind='oci',artifact_stem='cpu-image',transport_schema=2)
def check(data):
 table={BASE:data['repository'],RUNPATH:data['run'],RUNPATH+'/attempts/1':data['attempt'],BASE+'/branches/dev':data['branch'],BASE+'/compare/'+data['run']['head_sha']+'...'+data['branch']['commit']['sha']:data['compare'],RUNPATH+'/attempts/1/jobs?per_page=100&page=1':data['jobs'],BASE+'/actions/artifacts/'+str(ART):data['artifact'],RUNPATH+'/artifacts?per_page=100&page=1':data['artifacts']}
 return v.verify_metadata(lambda path:copy.deepcopy(table[path]),POLICY,RUN,1,ART,now='2026-10-19T02:32:00Z')
def in_progress():
 data=copy.deepcopy(FIXTURE)
 # Explicit adaptation: the retained terminal snapshot has overall failure.
 for key in ('run','attempt'):data[key].update(status='in_progress',conclusion=None)
 return data
@pytest.mark.parametrize('event',['push','workflow_dispatch'])
def test_allowed_protected_event_with_actual_associated_pr_passes_all_other_proofs(event):
 data=in_progress()
 for key in ('run','attempt'):data[key]['event']=event
 assert data['run']['pull_requests'][0]['number']==4
 proof=check(data)
 assert proof['head_sha']=='6ec08d6da25376d3c1f94ab46d7693c1d8f8e4d2' and proof['artifact_id']==ART and proof['event']==event
@pytest.mark.parametrize('event',['pull_request','pull_request_target'])
def test_pr_events_stay_denied_even_with_matching_association(event):
 data=in_progress()
 for key in ('run','attempt'):data[key]['event']=event
 with pytest.raises(v.Refused,match='protected source event'):check(data)
@pytest.mark.parametrize('value',[None,{},'[]'])
def test_informational_pr_field_still_requires_api_list_shape(value):
 data=in_progress();data['run']['pull_requests']=value
 with pytest.raises(v.Refused,match='protected source event'):check(data)
@pytest.mark.parametrize('case',['repository','branch','sha','workflow','recipe','producer','artifact'])
def test_association_cannot_replace_other_independent_proof(case):
 data=in_progress()
 if case=='repository':data['repository']['id']=1
 elif case=='branch':data['branch']['protected']=False
 elif case=='sha':data['attempt']['head_sha']='b'*40
 elif case=='workflow':data['run']['path']='.github/workflows/other.yml'
 elif case=='recipe':data['run']['referenced_workflows'][0]['sha']='b'*40
 elif case=='producer':data['jobs']['jobs'][0]['conclusion']='failure'
 else:data['artifact']['workflow_run']['head_sha']='b'*40
 with pytest.raises(v.Refused):check(data)
def test_raw_retained_terminal_snapshot_next_refuses_failed_overall_run():
 assert FIXTURE['run']['status']=='completed' and FIXTURE['run']['conclusion']=='failure'
 with pytest.raises(v.Refused,match='producer run state'):check(copy.deepcopy(FIXTURE))
def test_queued_run_still_requires_existing_explicit_policy_flag():
 data=in_progress()
 for key in ('run','attempt'):data[key]['status']='queued'
 assert POLICY.allow_queued_run is False
 with pytest.raises(v.Refused,match='producer run state'):check(data)
