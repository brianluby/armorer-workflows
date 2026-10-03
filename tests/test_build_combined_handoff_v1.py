"""Cross-component rejection tests use synthetic provider records and inert, unexecuted artifacts."""
import copy
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from armorer_runtime import combined_handoff_v1 as combined, policy_v1 as policy, transport_v1 as transport
from armorer_runtime.common import Failure
from armorer_runtime.final_payload_v1 import PayloadExpectation
from armorer_runtime.policy_transport_v1 import ExpectedPolicyRun
from test_build_handoff_v3 import create, TOOLS
import tests_policy_v1 as policy_fixtures


def zipped(root):
    """Retain an exact provider-shaped ZIP over synthetic bytes, never run its executable member."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
        for leaf in sorted(root.iterdir()):
            archive.writestr(leaf.name, leaf.read_bytes())
    return stream.getvalue()


def fixture(root):
    """Compose independently fixed build/policy expectations and matching synthetic unsigned reports."""
    build_root, policy_root = root/'build', root/'policy'
    build_root.mkdir()
    policy_root.mkdir()
    selected, handoff, inventory = create(build_root)
    envelope, (context, _, inputs, helpers, catalog, project_policy) = policy_fixtures.ReportBoundaryTests().fixture(policy_root)
    build_context = {key: value for key, value in context.items() if key not in ('event', 'ref')}
    hashes = {name: inputs[name]['sha256'] for name in ('armorer.toml', 'armorer.lock', 'Cargo.lock')}
    graph_path = build_root/(selected['artifact_id']+'.cargo-graph.json')
    graph = json.loads(graph_path.read_bytes())
    graph.update(**build_context, input_sha256=hashes)
    graph['run_id'], graph['run_attempt'] = 17, 2
    graph_path.write_text(json.dumps(graph))
    inventory.update(**build_context, input_sha256=hashes)
    inventory['source_input_sha256'] = {name:identity['sha256'] for name,identity in inputs.items()}
    inventory['files'][2].update(size=graph_path.stat().st_size, sha256=hashlib.sha256(graph_path.read_bytes()).hexdigest())
    (build_root/'inventory.json').write_text(json.dumps(inventory))
    handoff.update(**build_context, input_sha256=hashes, observed_build={'started_at':1000, 'finished_at':1001})
    data = (build_root/'inventory.json').read_bytes()
    handoff['build_inventory'] = {'size':len(data), 'sha256':hashlib.sha256(data).hexdigest()}
    (build_root/'handoff-v3.json').write_text(json.dumps(handoff))
    envelope['selection'] = selected
    envelope['tools'] = {name:{'version':tool['version'], 'target':selected['target'], **tool['platforms'][selected['target']]}
                         for name, tool in catalog['catalog']['tools'].items()}
    (policy_root/'policy-v1.json').write_bytes(policy.canonical(envelope))
    expected_build = transport.ExpectedRun('fixture/build', 33, 'e'*40, 'a'*40, 'feature', 'pull_request',
                                           '.github/workflows/combined.yml', 44, 17, 2, 'b'*40)
    expected_policy = ExpectedPolicyRun('fixture/build', 33, 'e'*40, 'a'*40, 'feature', 'pull_request',
        'refs/pull/17/merge', '.github/workflows/combined.yml', 44, 17, 2, 'b'*40)
    expected = combined.CombinedRun(expected_build, expected_policy, True)
    item = PayloadExpectation(selected, build_context, hashes, 'app', '0.1.0', TOOLS)
    repository = {'id':33, 'full_name':'fixture/build', 'fork':False}
    run = {'id':17, 'run_attempt':2, 'workflow_id':44, 'head_sha':'e'*40, 'head_branch':'feature',
           'event':'pull_request', 'path':'.github/workflows/combined.yml', 'repository':repository,
           'head_repository':copy.deepcopy(repository), 'status':'in_progress', 'conclusion':None,
           'run_started_at':'1970-01-01T00:16:40Z', 'referenced_workflows':[
               {'path':'brianluby/armorer-workflows/'+path+'@'+'b'*40,'sha':'b'*40}
               for path in (expected_build.builder_path, '.github/workflows/rust-policy-v1.yml')],
           'pull_requests':[{'number':17,'head':{'sha':'e'*40,'ref':'feature','repo':{'id':33}}}]}
    blobs = {55:zipped(build_root), 56:zipped(policy_root)}
    names = [selected['artifact_id']+'-handoff-v3-run-17-attempt-2', 'policy-v1-'+selected['artifact_id']+'-17-2']
    rows = [{'id':ident, 'name':name, 'expired':False, 'size_in_bytes':len(blobs[ident]),
             'digest':'sha256:'+hashlib.sha256(blobs[ident]).hexdigest(),
             'workflow_run':{'id':17,'repository_id':33,'head_repository_id':33,'head_sha':'e'*40,'head_branch':'feature'},
             'created_at':'1970-01-01T00:16:42Z','updated_at':'1970-01-01T00:16:42Z','expires_at':'1970-01-02T00:16:42Z'}
            for ident, name in zip(blobs, names)]
    state = {'run':run, 'attempt':copy.deepcopy(run), 'listing':{'total_count':2,'artifacts':rows},
             'details':{row['id']:copy.deepcopy(row) for row in rows},'blobs':blobs,'downloads':[], 'reads':[]}
    api = transport.QualifiedGhApi.operator_qualification(Path('/unused-synthetic-native-gh'))

    def read(endpoint):
        """Record fixed reads and return only copied test-owned metadata."""
        state['reads'].append(endpoint)
        value = state['listing'] if '/artifacts?' in endpoint else state['details'][int(endpoint.rsplit('/',1)[1])] \
            if '/artifacts/' in endpoint else state['attempt'] if '/attempts/' in endpoint else state['run']
        return copy.deepcopy(value)

    def download(repository_name, ident, destination):
        """Write inert ZIP bytes as a mock storage server; this is never real provider qualification."""
        assert repository_name == 'fixture/build'
        state['downloads'].append(ident)
        destination.write_bytes(state['blobs'][ident])

    api.json, api.archive = read, download
    return state, (api, expected, (item,), inputs, helpers, catalog, project_policy)


class CombinedHandoffTests(unittest.TestCase):
    """Reject whole-set substitutions and mutable races across both existing versioned semantics."""

    def test_complete_set_checks_both_semantics_and_removes_private_inert_snapshot(self):
        """Both archive types are retained read-only only while the owner context remains open."""
        with tempfile.TemporaryDirectory() as temporary:
            state, args = fixture(Path(temporary))
            with mock.patch.object(combined.time, 'time', return_value=1003):
                with combined.collect_producer_handoffs(*args) as (builds, policies, receipt):
                    self.assertEqual(set(builds), set(policies))
                    self.assertEqual(len(receipt['artifacts']), 2)
                    self.assertEqual(len(receipt['semantics']), 1)
                    self.assertEqual(sorted(state['downloads']), [55,56])
                    folder = next(iter(builds.values()))
                    self.assertFalse((folder/'executed').exists())
                    for directory in (*builds.values(), *policies.values()):
                        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o400 for p in directory.iterdir()))
                    for flag in ('signing_authorized','publication_authorized','production_catalog_accepted',
                                 'producer_job_authenticated','artifact_producer_authenticated','cryptographic_release_authenticated'):
                        self.assertIs(receipt[flag], False)
                    with self.assertRaises(TypeError):
                        builds['offered'] = folder
                self.assertFalse(folder.exists())

    def test_independent_context_and_source_input_mismatch_fail_before_network(self):
        """No run/source/ref/selection or source-policy mismatch reaches credentials or transport reads."""
        for case in ('run','runtime','source','qualification','duplicate','inputs','limit'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                state, args = fixture(Path(temporary))
                api, expected, items, inputs, helpers, catalog, project_policy = args
                if case in ('run','runtime','source'):
                    name, value = {'run':('run_attempt',3),'runtime':('runtime_commit','f'*40),'source':('source_commit','f'*40)}[case]
                    expected = replace(expected, policy=replace(expected.policy, **{name:value}))
                elif case == 'qualification': expected = replace(expected, qualification_only=False)
                elif case == 'duplicate': items += items
                elif case == 'limit': items *= 33
                else: inputs['armorer.toml']['sha256'] = 'f'*64
                with self.assertRaises(Failure):
                    with combined.collect_producer_handoffs(api,expected,items,inputs,helpers,catalog,project_policy):
                        self.fail('invalid expectations yielded a snapshot')
                self.assertEqual(state['reads'], [])

    def test_provider_pin_attempt_pr_fork_failure_and_ambiguous_sets_prevent_download(self):
        """A combined active run still requires both exact reusable pins and one complete expected set."""
        mutations = [lambda s:s['run'].update(run_attempt=3), lambda s:s['run'].update(status='completed',conclusion='success'),
            lambda s:s['run']['referenced_workflows'][1].update(sha='f'*40),
            lambda s:s['run']['referenced_workflows'].append(copy.deepcopy(s['run']['referenced_workflows'][1])),
            lambda s:s['run']['head_repository'].update(fork=True),
            lambda s:s['run']['pull_requests'][0]['head'].update(sha='f'*40),
            lambda s:s['listing'].update(total_count=3), lambda s:s['listing']['artifacts'].pop(),
            lambda s:s['listing']['artifacts'][1].update(name=s['listing']['artifacts'][0]['name']),
            lambda s:s['listing']['artifacts'][1]['workflow_run'].update(id=18)]
        for change in mutations:
            with tempfile.TemporaryDirectory() as temporary:
                state,args = fixture(Path(temporary));change(state)
                with mock.patch.object(combined.time,'time',return_value=1003), self.assertRaises(Failure):
                    with combined.collect_producer_handoffs(*args): self.fail('invalid provider yielded')
                self.assertEqual(state['downloads'], [])

    def test_tampered_archives_fail_before_zip_decoding_and_never_execute_payload(self):
        """Both build and policy ZIP hashes are checked before any decompression or artifact use."""
        for ident in (55,56):
            with tempfile.TemporaryDirectory() as temporary:
                state,args = fixture(Path(temporary));state['blobs'][ident] += b'tamper'
                original = combined._expansion_size
                opened = []
                def inspect(path, kind, selection):
                    """Record only valid archive decoding; the changed object must never reach this function."""
                    opened.append(int(path.stem));return original(path,kind,selection)
                with mock.patch.object(combined,'_expansion_size',side_effect=inspect), \
                     mock.patch.object(combined.time,'time',return_value=1003), self.assertRaises(Failure):
                    with combined.collect_producer_handoffs(*args): self.fail('tampered transport yielded')
                self.assertNotIn(ident,opened)

    def test_final_rerun_storage_detail_and_local_leaf_mutation_reject_whole_set(self):
        """Late changes cannot preserve an earlier valid run or a copied unsigned report."""
        for case in ('rerun','storage','detail','local'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                state,args = fixture(Path(temporary));original = args[0].archive
                def changed(repository, ident, destination):
                    """Mutate a prerequisite after download so the final whole-set reread must reject."""
                    original(repository,ident,destination)
                    if ident != 56:return
                    if case == 'rerun':state['run']['run_attempt']=3
                    elif case == 'storage':state['listing']['artifacts'][0]['id']=57
                    elif case == 'detail':state['details'][55]['digest']='sha256:'+'f'*64
                    else:
                        key=args[2][0].selection['artifact_id']
                        leaf=destination.parent/('build-'+key)/(key+'.bin')
                        leaf.chmod(0o600);leaf.write_bytes(b'tampered')
                args[0].archive=changed
                with mock.patch.object(combined.time,'time',return_value=1003), self.assertRaises((Failure,ValueError)):
                    with combined.collect_producer_handoffs(*args):self.fail('raced snapshot yielded')

    def test_whole_staging_budget_is_checked_before_expansion(self):
        """A small total budget rejects ZIP expansion without writing decoded files."""
        with tempfile.TemporaryDirectory() as temporary:
            state,args=fixture(Path(temporary))
            bound=sum(len(data) for data in state['blobs'].values())
            with mock.patch.object(combined,'MAX_TOTAL',bound), mock.patch.object(combined.time,'time',return_value=1003), \
                 mock.patch.object(transport,'_unpack_provider_zip') as unpack, self.assertRaises(Failure):
                with combined.collect_producer_handoffs(*args):self.fail('oversized staging yielded')
            unpack.assert_not_called()

    def test_self_consistent_build_source_rewrite_and_policy_failure_reject(self):
        """Updated unsigned hashes cannot hide a different build tree or failed native policy report."""
        for case in ('source','policy'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);state,args=fixture(root)
                if case == 'source':
                    folder=root/'build'
                    inventory=json.loads((folder/'inventory.json').read_bytes())
                    inventory['source_input_sha256']['armorer.toml']='f'*64
                    (folder/'inventory.json').write_text(json.dumps(inventory))
                    handoff=json.loads((folder/'handoff-v3.json').read_bytes())
                    raw=(folder/'inventory.json').read_bytes()
                    handoff['build_inventory']={'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
                    (folder/'handoff-v3.json').write_text(json.dumps(handoff));ident=55
                else:
                    folder=root/'policy'
                    raw=b'[{"finding":"test-only-policy-failure"}]'
                    (folder/'actionlint.json').write_bytes(raw)
                    envelope=json.loads((folder/'policy-v1.json').read_bytes())
                    envelope['reports']['actionlint.json']={'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
                    (folder/'policy-v1.json').write_bytes(policy.canonical(envelope));ident=56
                state['blobs'][ident]=zipped(folder)
                for row in (next(row for row in state['listing']['artifacts'] if row['id']==ident), state['details'][ident]):
                    row.update(size_in_bytes=len(state['blobs'][ident]),digest='sha256:'+hashlib.sha256(state['blobs'][ident]).hexdigest())
                with mock.patch.object(combined.time,'time',return_value=1003), self.assertRaises(Failure):
                    with combined.collect_producer_handoffs(*args):self.fail('rewritten unsigned metadata yielded')

    def test_independent_inputs_are_frozen_and_final_freshness_rechecked(self):
        """External expectation mutation cannot retarget a collection, and expiry rejects its final boundary."""
        with tempfile.TemporaryDirectory() as temporary:
            state,args=fixture(Path(temporary));original=args[0].archive
            def changed(repository, ident, destination):
                """Attempt to rewrite the external policy after collection has copied its independent expectations."""
                original(repository,ident,destination)
                args[3]['armorer.toml']['sha256']='f'*64
                args[6]['licenses']['allow']=[]
            args[0].archive=changed
            with mock.patch.object(combined.time,'time',return_value=1003):
                with combined.collect_producer_handoffs(*args) as (_,__,receipt):
                    self.assertEqual(receipt['state'],'combined-build-policy-transport-observed')
        with tempfile.TemporaryDirectory() as temporary:
            _,args=fixture(Path(temporary));original=combined._semantics
            def expire(*values):
                """Advance only the test clock after the first complete semantic check."""
                result=original(*values)
                combined.time.time=lambda:4601
                return result
            with mock.patch.object(combined.time,'time',return_value=1003), \
                 mock.patch.object(combined,'_semantics',side_effect=expire), self.assertRaises(Failure):
                with combined.collect_producer_handoffs(*args):self.fail('expired snapshot yielded')
