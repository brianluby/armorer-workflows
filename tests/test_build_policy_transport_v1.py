"""Synthetic provider-boundary adversaries; real native API qualification is a separate gate."""

import copy
from dataclasses import replace
import io
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

from armorer_runtime import common, policy_tools_v1 as pins, policy_transport_v1 as transport, policy_v1 as policy
import tests_policy_v1 as fixtures


class PolicyTransportTests(unittest.TestCase):
    """Fail the complete collector for substituted provider, archive or report observations."""

    def fixture(self, root):
        """Create a synthetic complete native-shaped report and a recording GET-only provider stub."""
        envelope, (context, selection, inputs, helpers, catalog, project_policy) = fixtures.ReportBoundaryTests().fixture(root)
        expected = transport.ExpectedPolicyRun('fixture/build', 33, 'e' * 40, 'a' * 40, 'fixture-policy',
            'pull_request', 'refs/pull/17/merge', '.github/workflows/policy.yml', 44, 17, 2, 'b' * 40)
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
            for leaf in sorted(root.iterdir()):
                archive.writestr(leaf.name, leaf.read_bytes())
        data = output.getvalue()
        repository = {'id': 33, 'full_name': 'fixture/build', 'fork': False}
        run = {'id': 17, 'run_attempt': 2, 'workflow_id': 44, 'head_sha': 'e' * 40,
            'head_branch': 'fixture-policy', 'event': 'pull_request', 'path': '.github/workflows/policy.yml',
            'repository': repository, 'head_repository': repository, 'status': 'completed', 'conclusion': 'success',
            'referenced_workflows': [{'path': 'brianluby/armorer-workflows/' + transport.POLICY_WORKFLOW + '@' + 'b' * 40, 'sha': 'b' * 40}],
            'pull_requests': [{'number': 17, 'head': {'sha': 'e' * 40, 'ref': 'fixture-policy', 'repo': {'id': 33}}}],
            'run_started_at': '1970-01-01T00:16:40Z'}
        name = f'policy-v1-{selection["artifact_id"]}-17-2'
        identity = pins.identity(data)
        artifact = {'id': 55, 'name': name, 'expired': False, 'digest': 'sha256:' + identity['sha256'],
            'size_in_bytes': identity['size'], 'created_at': '1970-01-01T00:16:42Z',
            'updated_at': '1970-01-01T00:16:42Z', 'expires_at': '1970-01-02T00:16:42Z',
            'workflow_run': {'id': 17, 'repository_id': 33, 'head_repository_id': 33,
                             'head_sha': 'e' * 40, 'head_branch': 'fixture-policy'}}
        records = {'run': run, 'attempt': copy.deepcopy(run), 'listing': {'total_count': 1, 'artifacts': [artifact]},
                   'detail': copy.deepcopy(artifact), 'data': data, 'reads': [], 'downloads': 0}
        api = transport.QualifiedGhApi.operator_qualification(Path('/unused-synthetic-native-gh'))

        def read(endpoint):
            """Return explicitly synthetic records while recording only exact collector GET routes."""
            records['reads'].append(endpoint)
            key = 'listing' if '/artifacts?' in endpoint else 'detail' if '/artifacts/55' in endpoint else 'attempt' if '/attempts/2' in endpoint else 'run'
            return copy.deepcopy(records[key])

        def download(repository_name, artifact_id, destination):
            """Write the inert synthetic ZIP; never invoke an executable or publish a remote asset."""
            self.assertEqual((repository_name, artifact_id), ('fixture/build', 55))
            records['downloads'] += 1
            destination.write_bytes(records['data'])

        api.json = read
        api.archive = download
        arguments = (api, expected, [selection], inputs, helpers, catalog, project_policy)
        return records, arguments

    def test_complete_collection_yields_private_inert_reports_without_authority(self):
        """A matching synthetic snapshot stays unsigned and its private files disappear on context exit."""
        with tempfile.TemporaryDirectory() as temporary:
            records, args = self.fixture(Path(temporary))
            with mock.patch.object(transport.time, 'time', return_value=1003):
                with transport.collect_policy(*args) as (directories, receipt):
                    self.assertEqual(records['downloads'], 1)
                    folder = next(iter(directories.values()))
                    self.assertEqual({leaf.name for leaf in folder.iterdir()}, policy.REPORT_NAMES | {'policy-v1.json'})
                    self.assertTrue(all(leaf.stat().st_mode & 0o777 == 0o400 for leaf in folder.iterdir()))
                    self.assertFalse(receipt['signing_authorized'])
                    self.assertFalse(receipt['producer_job_authenticated'])
                    self.assertFalse(receipt['cryptographic_release_authenticated'])
                self.assertFalse(folder.exists())

    def test_provider_source_attempt_ref_pin_and_failure_rejected_before_download(self):
        """Substituted source, failed jobs, forks, reruns and foreign workflow pins never reach artifact reads."""
        changes = [('head_sha', 'f' * 40), ('run_attempt', 3), ('conclusion', 'failure'),
                   ('status', 'in_progress'), ('event', 'pull_request_target'), ('workflow_id', True)]
        for key, value in changes:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                records, args = self.fixture(Path(temporary))
                records['run'][key] = value
                with mock.patch.object(transport.time, 'time', return_value=1003), self.assertRaises(common.Failure):
                    with transport.collect_policy(*args):
                        self.fail('rejected context yielded reports')
                self.assertEqual(records['downloads'], 0)
        for field in ('fork', 'pin', 'ref'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                records, args = self.fixture(Path(temporary))
                if field == 'fork':
                    records['run']['head_repository']['fork'] = True
                elif field == 'pin':
                    records['run']['referenced_workflows'][0]['sha'] = 'f' * 40
                else:
                    records['run']['pull_requests'][0]['number'] = 18
                with mock.patch.object(transport.time, 'time', return_value=1003), self.assertRaises(common.Failure):
                    with transport.collect_policy(*args):
                        self.fail('rejected provider yielded reports')
                self.assertEqual(records['downloads'], 0)

    def test_partial_extra_duplicate_and_crossrun_storage_sets_fail(self):
        """One exact complete provider set is required before downloading any report archive."""
        for kind in ('missing', 'extra', 'duplicate', 'crossrun', 'expired', 'digest'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                records, args = self.fixture(Path(temporary))
                if kind == 'missing':
                    records['listing'] = {'total_count': 0, 'artifacts': []}
                elif kind in ('extra', 'duplicate'):
                    records['listing']['artifacts'].append(copy.deepcopy(records['listing']['artifacts'][0]))
                    records['listing']['total_count'] = 2
                else:
                    artifact = records['listing']['artifacts'][0]
                    if kind == 'crossrun':
                        artifact['workflow_run']['id'] = 18
                    elif kind == 'expired':
                        artifact['expired'] = True
                    else:
                        artifact['digest'] = 'sha256:' + 'z' * 64
                with mock.patch.object(transport.time, 'time', return_value=1003), self.assertRaises(common.Failure):
                    with transport.collect_policy(*args):
                        self.fail('rejected storage yielded reports')
                self.assertEqual(records['downloads'], 0)

    def test_whole_archive_digest_precedes_any_zip_parser(self):
        """A tampered transport archive is rejected without opening even its central directory."""
        with tempfile.TemporaryDirectory() as temporary:
            records, args = self.fixture(Path(temporary))
            records['data'] += b'tamper'
            with mock.patch.object(transport.time, 'time', return_value=1003), mock.patch.object(transport.zipfile, 'ZipFile') as parser:
                with self.assertRaises(common.Failure):
                    with transport.collect_policy(*args):
                        self.fail('tampered bytes yielded reports')
                parser.assert_not_called()

    def test_zip_alias_symlink_extra_and_trailing_bytes_fail_closed(self):
        """Seven nominal entries cannot legitimize path escapes, executable links or extra container bytes."""
        for kind in ('alias', 'symlink', 'extra', 'trailing'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, args = self.fixture(root)
                output = io.BytesIO()
                with zipfile.ZipFile(output, 'w') as archive:
                    for name in policy.REPORT_NAMES | {'policy-v1.json'}:
                        info = zipfile.ZipInfo('../' + name if kind == 'alias' else name)
                        info.external_attr = (stat.S_IFLNK | 0o777) << 16 if kind == 'symlink' else (stat.S_IFREG | 0o400) << 16
                        archive.writestr(info, (root / name).read_bytes())
                    if kind == 'extra':
                        archive.writestr('extra', b'extra')
                data = output.getvalue() + (b'trailing' if kind == 'trailing' else b'')
                path = root / 'offered.zip'
                path.write_bytes(data)
                with self.assertRaises(common.Failure):
                    transport._unpack(path, root / 'private', args[2][0])

    def test_final_provider_race_and_current_clock_expiry_never_yield(self):
        """A successful initial read cannot survive a mutable rerun, storage replacement or elapsed freshness limit."""
        for kind in ('rerun', 'storage', 'head-tip', 'expiry'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                records, args = self.fixture(Path(temporary))
                original = args[0].archive

                def changed(repository, artifact_id, destination):
                    """Simulate one mutation after a real-shaped download and before final provider rereads."""
                    original(repository, artifact_id, destination)
                    if kind == 'rerun':
                        records['run']['run_attempt'] = 3
                    elif kind == 'storage':
                        records['listing']['artifacts'][0]['id'] = 56
                    elif kind == 'head-tip':
                        records['run']['pull_requests'][0]['head']['sha'] = 'f' * 40

                args[0].archive = changed
                clock = iter([1003, 1003, 1003, 1003, 4601]) if kind == 'expiry' else None
                with mock.patch.object(transport.time, 'time', side_effect=lambda: next(clock, 4601)) if clock else mock.patch.object(transport.time, 'time', return_value=1003):
                    with self.assertRaises(common.Failure):
                        with transport.collect_policy(*args):
                            self.fail('mutable or expired provider yielded reports')

    def test_independent_source_runtime_policy_and_duplicate_selection_rejected(self):
        """Matching unsigned data never substitutes for independently supplied expectations."""
        with tempfile.TemporaryDirectory() as temporary:
            records, args = self.fixture(Path(temporary))
            for index in (3, 4, 6):
                offered = list(args)
                offered[index] = {}
                with self.subTest(index=index), mock.patch.object(transport.time, 'time', return_value=1003), self.assertRaises(common.Failure):
                    with transport.collect_policy(*offered):
                        self.fail('wrong independent expectation yielded reports')
            offered = list(args)
            offered[2] = args[2] * 2
            with mock.patch.object(transport.time, 'time', return_value=1003), self.assertRaises(common.Failure):
                with transport.collect_policy(*offered):
                    self.fail('duplicate selection yielded reports')
            for value in (replace(args[1], event='pull_request_target'), replace(args[1], ref='refs/pull/0/merge'),
                          replace(args[1], max_age_seconds=3601), replace(args[1], run_id=True)):
                with self.subTest(value=value), self.assertRaises(common.Failure):
                    value.validate()

    def test_exception_expiry_at_final_transport_boundary_cannot_yield(self):
        """A date rollover after the last reader check must still reject an expiring advisory exception."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records, args = self.fixture(root)
            envelope = policy.parse_json((root / 'policy-v1.json').read_bytes())
            envelope['observed'] = {'started_at': 86398, 'finished_at': 86399}
            args[6]['advisories']['exceptions'] = [{'id': 'RUSTSEC-2020-0001', 'owner': 'fixture',
                'reason': 'synthetic rollover test', 'expires': '1970-01-01'}]
            envelope['effective_policy'] = args[6]
            database = policy.parse_json((root / 'advisory-db.json').read_bytes())
            database['fetched_at'] = 86398
            data = policy.canonical(database)
            (root / 'advisory-db.json').write_bytes(data)
            envelope['reports']['advisory-db.json'] = pins.identity(data)
            (root / 'policy-v1.json').write_bytes(policy.canonical(envelope))
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
                for leaf in root.iterdir():
                    archive.writestr(leaf.name, leaf.read_bytes())
            records['data'] = output.getvalue()
            identity = pins.identity(records['data'])
            for record in (records['run'], records['attempt']):
                record['run_started_at'] = '1970-01-01T23:59:58Z'
            for record in (records['listing']['artifacts'][0], records['detail']):
                record.update({'digest': 'sha256:' + identity['sha256'], 'size_in_bytes': identity['size'],
                    'created_at': '1970-01-01T23:59:59Z', 'updated_at': '1970-01-01T23:59:59Z',
                    'expires_at': '1970-01-02T23:59:59Z'})
            with mock.patch.object(transport.time, 'time', side_effect=[86399] * 7 + [86400]):
                with self.assertRaisesRegex(common.Failure, 'exception expired at transport boundary'):
                    with transport.collect_policy(*args):
                        self.fail('expired exception yielded reports')

    def test_semantically_valid_leaf_replacement_cannot_change_receipt_bytes(self):
        """Another valid JSON encoding cannot replace authenticated leaf bytes while keeping the old receipt."""
        with tempfile.TemporaryDirectory() as temporary:
            records, args = self.fixture(Path(temporary))
            original_download = args[0].archive
            original_read = args[0].json
            state = {}

            def download(repository, artifact_id, destination):
                """Record the private directory location after creating the unchanged authenticated ZIP."""
                original_download(repository, artifact_id, destination)
                state['directory'] = destination.parent / args[2][0]['artifact_id']

            def read(endpoint):
                """Substitute a self-consistent valid report after the first reader and before final validation."""
                if endpoint.endswith('/runs/17') and 'directory' in state and not state.get('changed'):
                    directory = state['directory']
                    report = directory / 'actionlint.json'
                    report.chmod(0o600)
                    report.write_bytes(b'[] ')
                    envelope_path = directory / 'policy-v1.json'
                    envelope = policy.parse_json(envelope_path.read_bytes())
                    envelope['reports']['actionlint.json'] = pins.identity(report.read_bytes())
                    envelope_path.chmod(0o600)
                    envelope_path.write_bytes(policy.canonical(envelope))
                    policy.verify(directory, args[1].context(), args[2][0], *args[3:], now=1003)
                    state['changed'] = True
                return original_read(endpoint)

            args[0].archive = download
            args[0].json = read
            with mock.patch.object(transport.time, 'time', return_value=1003):
                with self.assertRaisesRegex(common.Failure, 'policy snapshot leaf changed'):
                    with transport.collect_policy(*args):
                        self.fail('replacement bytes yielded an obsolete receipt')
            self.assertTrue(state['changed'])


if __name__ == '__main__':
    unittest.main()
