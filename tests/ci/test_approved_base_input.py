"""Run the actual build shell CLI with fake Docker/Maven and a small context.

No registry, daemon, package network, or real compiler is used. The Docker fake
resolves the actual Dockerfile's global ARG/FROM prefix and records build input.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
AUTHOR_PHASE_FIXED = True
A = 'sha256:' + 'a' * 64
B = 'sha256:' + 'b' * 64
HUB = 'quay.io/noirolabs'
TAG = '6.1.1.8.fixture'

FAKE = r'''#!/usr/bin/env python3
import json, os, pathlib, re, subprocess, sys, time
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
log = pathlib.Path(os.environ['FIXTURE_LOG'])
def record(**data):
    with log.open('a') as stream: stream.write(json.dumps({'tool': name, **data}) + '\n')
if name == 'docker':
    data = {'argv': args}
    if args and args[0] == 'build':
        source = pathlib.Path(args[args.index('-f') + 1])
        values = {}
        for index, value in enumerate(args):
            if value == '--build-arg':
                key, item = args[index + 1].split('=', 1); values[key] = item
        def expand(value):
            return re.sub(r'\$\{([^}]+)\}', lambda match: values.get(match[1], ''), value)
        for line in source.read_text().splitlines():
            if line.startswith('ARG '):
                item = line[4:]; key, equal, default = item.partition('=')
                if key not in values: values[key] = expand(default) if equal else ''
            elif line.startswith('FROM '):
                data['resolved_from'] = expand(line[5:])
                data['resolved_base_digest'] = data['resolved_from'].split('@', 1)[1] if '@' in data['resolved_from'] else os.environ['FIXTURE_TAG_AT_BUILD_DIGEST']
                break
    record(**data)
    if args[:2] == ['image', 'inspect']:
        print(os.environ['FIXTURE_HUB'] + '/opflex-build-base@' + os.environ['FIXTURE_ACTUAL_DIGEST'])
    elif args and args[0] == 'create': print('fixture-container')
elif name == 'mvn': record(argv=args)
elif name == 'tar':
    if args and args[0] in ('czf', 'cvfz'):
        pathlib.Path(args[1]).write_bytes(b'fixture-source-archive')
    elif '-x' in args:
        sys.stdin.buffer.read()
        if '-C' in args:
            target = pathlib.Path(args[args.index('-C')+1]); (target/'bin').mkdir(parents=True, exist_ok=True)
    else: sys.stdin.buffer.read()
elif name == 'pgrep':
    time.sleep(0.02)
    result = subprocess.run(['/usr/bin/pgrep', '-f', re.escape(str(pathlib.Path(sys.argv[0]).with_name('docker'))) + r' build'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sys.stdout.buffer.write(result.stdout); raise SystemExit(result.returncode)
elif name == 'sleep': time.sleep(0.005)
# tail intentionally exits; no background reader survives the fixture.
'''


class ApprovedBaseInput(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='opflex-input-')
        self.directory = Path(self.temp.name)
        self.repo = self.directory / 'opflex'
        docker = self.repo / 'docker/travis'
        docker.mkdir(parents=True)
        for name in ('build-opflex-travis.sh', 'Dockerfile-opflex-build', 'Dockerfile-opflex-build-base', 'Dockerfile-opflex', 'Dockerfile-opflexserver'):
            shutil.copy2(ROOT / 'docker/travis' / name, docker / name)
        for name in ('launch-opflexagent.sh', 'launch-mcastdaemon.sh', 'launch-opflexserver.sh'):
            (docker / name).write_text('# fixture launcher\n')
        (self.repo / 'docker/licenses').mkdir()
        (self.repo / 'docker/licenses/fixture.txt').write_text('fixture license\n')
        (self.repo / 'genie').mkdir()
        self.bin = self.directory / 'bin'; self.bin.mkdir()
        for name in ('docker', 'mvn', 'tar', 'tail', 'sleep', 'pgrep'):
            path = self.bin / name; path.write_text(FAKE); path.chmod(0o755)
        self.log = self.directory / 'commands.jsonl'
        self.env = {'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
            'TRAVIS_TAG': '6.1.1.8', 'GITHUB_ACTIONS': 'true', 'GHA_OPFLEX_BUILD_PHASE': 'runtime',
            'GHA_PLATFORM': 'linux/amd64', 'CI_EVIDENCE_MODE': 'prepared-v1',
            'EXPECTED_OPFLEX_BASE_DIGEST': A, 'CI_ARTIFACT_DIR': str(self.repo / 'artifacts'),
            'FIXTURE_LOG': str(self.log), 'FIXTURE_ACTUAL_DIGEST': A, 'FIXTURE_HUB': HUB,
            'FIXTURE_TAG_AT_BUILD_DIGEST': B}

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, expected=0):
        result = subprocess.run(['bash', 'docker/travis/build-opflex-travis.sh', HUB, TAG, ''],
            cwd=self.repo, env=self.env, text=True, capture_output=True, timeout=15)
        if expected == 0: self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else: self.assertNotEqual(result.returncode, 0)
        return result

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def image_build(self):
        return next(item for item in self.commands() if item['tool']=='docker' and item['argv'][0]=='build'
                    and item['argv'][item['argv'].index('-f')+1].endswith('/Dockerfile-opflex-build'))

    def test_prepared_runtime_uses_digest_even_when_tag_moves_before_build(self):
        self.invoke()
        build = self.image_build()
        reference = HUB + '/opflex-build-base@' + A
        self.assertIn('OPFLEX_BUILD_BASE_IMAGE=' + reference, build['argv'])
        self.assertEqual(build['resolved_from'], reference)
        self.assertEqual(build['resolved_base_digest'], A)
        self.assertNotEqual(build['resolved_base_digest'], self.env['FIXTURE_TAG_AT_BUILD_DIGEST'])
        pulls = [item['argv'] for item in self.commands() if item['tool']=='docker' and item['argv'][0]=='pull']
        self.assertEqual(pulls, [['pull', reference]])
        recorded = dict(line.split('=',1) for line in (self.repo/'artifacts/opflex-build-base-input.txt').read_text().splitlines())
        self.assertEqual(recorded, {'opflex_build_base_ref':reference,'opflex_build_base_digest':A})

    def test_missing_or_malformed_prepared_digest_stops_before_pull_maven_and_build(self):
        for value in (None, '', 'sha256:'+'a'*63, 'sha256:'+'g'*64, A+' --evil'):
            with self.subTest(value=value):
                if self.log.exists(): self.log.unlink()
                if value is None: self.env.pop('EXPECTED_OPFLEX_BASE_DIGEST',None)
                else: self.env['EXPECTED_OPFLEX_BASE_DIGEST']=value
                self.invoke(expected=1)
                self.assertEqual(self.commands(), [])

    def test_actual_digest_mismatch_stops_before_maven_or_build(self):
        self.env['FIXTURE_ACTUAL_DIGEST']=B
        self.invoke(expected=1)
        calls=self.commands()
        self.assertTrue(any(item['tool']=='docker' and item['argv'][:2]==['image','inspect'] for item in calls))
        self.assertFalse(any(item['tool']=='mvn' or (item['tool']=='docker' and item['argv'][0]=='build') for item in calls))

    def test_absent_prepared_mode_retains_tag_based_dockerfile_default(self):
        self.env.pop('CI_EVIDENCE_MODE')
        self.invoke()
        build=self.image_build()
        self.assertFalse(any(value.startswith('OPFLEX_BUILD_BASE_IMAGE=') for value in build['argv']))
        self.assertEqual(build['resolved_from'], HUB + '/opflex-build-base:' + TAG)

    def test_missing_runtime_phase_has_no_prepared_tag_fallback(self):
        self.env.pop('GHA_OPFLEX_BUILD_PHASE')
        self.invoke(expected=1)
        self.assertEqual(self.commands(),[])

    def test_base_phase_preserves_author_fix_or_remains_explicit_default_blocker(self):
        self.env['GHA_OPFLEX_BUILD_PHASE']='base'
        self.env.pop('EXPECTED_OPFLEX_BASE_DIGEST')
        result=self.invoke(expected=0 if AUTHOR_PHASE_FIXED else 1)
        calls=self.commands()
        if AUTHOR_PHASE_FIXED:
            builds=[item for item in calls if item['tool']=='docker' and item['argv'][0]=='build']
            self.assertEqual(len(builds),1)
            self.assertTrue(builds[0]['argv'][builds[0]['argv'].index('-f')+1].endswith('/Dockerfile-opflex-build-base'))
            self.assertFalse(any(item['tool']=='mvn' for item in calls))
        else:
            self.assertIn('parent phase fix is required',result.stderr)
            self.assertEqual(calls,[])


if __name__=='__main__': unittest.main()
