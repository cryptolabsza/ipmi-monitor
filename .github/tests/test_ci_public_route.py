"""Exercise each immutable public leaf guard and the retained real build steps."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SPEC = json.loads((HERE / 'ci_public_contract.json').read_text())


class PublicBuildRouteTest(unittest.TestCase):
    def recipes(self):
        for filename, expected in SPEC['recipes'].items():
            path = ROOT / '.github/workflows' / filename
            self.assertTrue(path.is_file(), 'immutable CPU recipe is missing: ' + filename)
            source = path.read_text()
            yield filename, source, yaml.safe_load(source), expected

    def test_actual_leaf_guards_match_owned_source_and_negative_fixtures(self):
        rid = SPEC['repository_id']
        for filename, source, data, expected in self.recipes():
            guard = data['jobs'][expected['job']]['if']
            self.assertIn("github.repository_id == '" + str(rid) + "'", guard)
            self.assertIn('github.event.pull_request.head.repo.id == ' + str(rid), guard)
            for fixture in json.loads((HERE / 'ci_public_guard_cases.json').read_text()):
                with self.subTest(recipe=filename, case=fixture['name']):
                    expression = guard
                    for key, value in sorted(fixture['github'].items(), key=lambda item: -len(item[0])):
                        expression = expression.replace(key, repr(value))
                    expression = expression.replace('&&', ' and ').replace('||', ' or ')
                    expression = re.sub(r'\btrue\b', 'True', expression)
                    expression = re.sub(r'\bfalse\b', 'False', expression)
                    tree = ast.parse(expression.strip(), mode='eval')
                    allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare,
                               ast.Eq, ast.Constant, ast.Load)
                    self.assertTrue(all(isinstance(node, allowed) for node in ast.walk(tree)))
                    self.assertEqual(eval(compile(tree, '<actual-job-guard>', 'eval'), {'__builtins__': {}}), fixture['allowed'])

    def test_public_build_routes_are_static_read_only_and_bounded(self):
        for filename, source, data, expected in self.recipes():
            with self.subTest(recipe=filename):
                job = data['jobs'][expected['job']]
                self.assertEqual(job['runs-on'], {'group': 'ci-build-public-ephemeral', 'labels': ['ci-linux-cpu-v1-r' + str(SPEC['repository_id'])]})
                self.assertEqual(data['permissions'], {'contents': 'read'})
                self.assertEqual(job['permissions'], {'contents': 'read'})
                self.assertEqual(job['timeout-minutes'], 45)
                for forbidden in ('secrets:', 'secrets.', ': write', 'inputs.', 'pull_request_target',
                                  'repository_dispatch', '--privileged', '--network host', '--volume', '--mount', '--device', 'continue-on-error'):
                    self.assertNotIn(forbidden, source)
                self.assertNotIn('needs', job)
                self.assertIn("python -m unittest discover -s .github/tests -p 'test_ci_public_route.py'", source)
                for step in job['steps']:
                    if 'uses' not in step:
                        continue
                    self.assertRegex(step['uses'], r'@[a-f0-9]{40}$')
                    if step['uses'].startswith('actions/checkout@'):
                        self.assertEqual(step['with']['ref'], '${{ github.sha }}')
                        self.assertIs(step['with']['persist-credentials'], False)
                    if step['uses'].startswith('docker/build-push-action@'):
                        self.assertIs(step['with']['push'], False)
                        self.assertIn('type=oci,', step['with']['outputs'])

    def test_original_functional_commands_remain_and_image_exports_are_retained(self):
        for filename, source, data, expected in self.recipes():
            steps = data['jobs'][expected['job']]['steps']
            commands = [step['run'] for step in steps if 'run' in step]
            for command in expected['commands']:
                self.assertIn(command, commands, filename)
            if 'python-build' in filename:
                self.assertIn('python -m build', source)
                self.assertIn('SHA256SUMS', source)
            elif 'pages-build' in filename:
                jekyll = next(step for step in steps if step.get('uses', '').startswith('actions/jekyll-build-pages@'))
                self.assertEqual(jekyll['with'], {'source': './docs', 'destination': './_site'})
                self.assertTrue(any(step.get('uses', '').startswith('actions/upload-pages-artifact@') for step in steps))
            else:
                self.assertIn('artifact_kind', source)
                self.assertIn('expected_image', source)
                self.assertIn('hashlib.sha256()', source)
                self.assertIn('artifact-digest', source)
                self.assertIn('${{ github.run_id }}-${{ github.run_attempt }}', source)

    def test_actual_image_receipt_script_checksums_exported_bytes(self):
        for filename, source, data, expected in self.recipes():
            if 'python-build' in filename or 'pages-build' in filename:
                continue
            steps = data['jobs'][expected['job']]['steps']
            script = next(s['run'] for s in steps if s.get('name') == 'Record fixed image identity and artifact checksum')
            upload = next(s for s in steps if s.get('id') == 'upload')
            self.assertNotIn('.ci-artifacts', upload['with']['path'], 'hidden directories are excluded by artifact upload defaults')
            archive_name = expected['job'] + '.tar'
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'ci-artifacts').mkdir()
                archive = root / 'ci-artifacts' / archive_name
                payload = b'exported image archive fixture'
                archive.write_bytes(payload)
                subprocess.run(['bash', '-euo', 'pipefail', '-c', script.replace('python - <<', repr(sys.executable) + ' - <<', 1)], cwd=root,
                               env={**os.environ, 'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2'},
                               capture_output=True, text=True, check=True)
                receipt = json.loads(archive.with_suffix('.json').read_text())
                self.assertEqual(receipt['sha256'], hashlib.sha256(payload).hexdigest())
                self.assertEqual(receipt['repository_id'], SPEC['repository_id'])
                self.assertEqual(receipt['source_sha'], 'a' * 40)
                self.assertEqual(receipt['run_attempt'], '2')
                self.assertIn(archive_name, upload['with']['path'])
                self.assertIn(archive.with_suffix('.json').name, upload['with']['path'])

    def test_callers_pin_immutable_recipes_without_credentials_or_source_inputs(self):
        for caller, recipe in SPEC['callers'].items():
            filename, jid = caller.split('#')
            job = yaml.safe_load((ROOT / '.github/workflows' / filename).read_text())['jobs'][jid]
            self.assertRegex(job['uses'], r'/\.github/workflows/' + re.escape(recipe) + r'@[0-9a-f]{40}$')
            self.assertNotIn('@' + '0' * 40, job['uses'])
            self.assertEqual(job['permissions'], {'contents': 'read'})
            self.assertNotIn('secrets', job)
            self.assertNotIn('with', job)

    def test_original_authority_commands_are_held_outside_cpu_admission(self):
        for target, expected in SPEC['held'].items():
            filename, jid = target.split('#')
            job = yaml.safe_load((ROOT / '.github/workflows' / filename).read_text())['jobs'][jid]
            self.assertEqual(job['runs-on'], ['self-hosted', 'ci-authority-held-r' + str(SPEC['repository_id'])])
            self.assertGreater(job['timeout-minutes'], 0)
            self.assertLessEqual(job['timeout-minutes'], 120)
            self.assertEqual([s['run'] for s in job['steps'] if 'run' in s], expected['commands'])
            for step in job['steps']:
                if 'uses' in step:
                    self.assertRegex(step['uses'], r'@[a-f0-9]{40}$')
                    if step['uses'].startswith('actions/checkout@'):
                        self.assertIs(step['with']['persist-credentials'], False)

    def test_only_official_apt_mirrors_change_to_https_when_needed(self):
        if SPEC['repository_id'] == 1140353276:
            return  # Alpine-based proxy has no Debian/Ubuntu APT path.
        helper = ROOT / '.github/ci/use-https-apt-mirrors.sh'
        self.assertTrue(helper.is_file())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'sources.list.d').mkdir()
            source = root / 'sources.list.d/debian.sources'
            source.write_text('URIs: http://deb.debian.org/debian http://security.debian.org/debian-security\n# http://vendor.example.invalid/repo\n')
            subprocess.run(['sh', str(helper), str(root)], check=True)
            self.assertEqual(source.read_text(), 'URIs: https://deb.debian.org/debian https://security.debian.org/debian-security\n# http://vendor.example.invalid/repo\n')
        dockerfile = (ROOT / 'Dockerfile').read_text()
        self.assertIn('sh /tmp/ci-use-https-apt-mirrors.sh && apt-get update', dockerfile)


if __name__ == '__main__':
    unittest.main()
