"""Read actual same-run build/policy archives and compare native final payload bytes, without signing."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import tempfile
import tomllib
import urllib.request

from armorer_runtime import ci, common, combined_handoff_v1 as combined, final_payload_v1 as final
from armorer_runtime import policy_tools_v1 as pins, policy_v1 as policy, tools, transport_v1 as transport
from armorer_runtime.transport_tools_v1 import install_gh
from armorer_runtime.policy_transport_v1 import ExpectedPolicyRun

RUNTIME = '59a2e782150abff3f995682013d514e6865d8dfb'
REPOSITORY = 'brianluby/armorer-workflows'
REPOSITORY_ID = 1398918288
CALLER = '.github/workflows/rehearsal-combined-v1.yml'
_cancelled = False
_apis = []


def cancel(_number, _frame):
    """Expire owned API stages cooperatively so native children complete their bounded cleanup."""
    global _cancelled
    _cancelled = True
    for api in _apis:
        api._deadline = 0


def checkpoint():
    """A cancelled qualification may not return a successful identity record."""
    common.require(not _cancelled, 'combined qualification cancelled')


def identity(data):
    """Hash actual retained bytes without treating a digest as accepted catalog authority."""
    return {'sha256':hashlib.sha256(data).hexdigest(), 'size':len(data)}


def tool_hashes(runtime):
    """Measure all three platforms' fixed catalog tool members without executing any downloaded tool."""
    catalog = json.loads(common.read_input(runtime, 'pins/tools.json'))
    result = {}
    for target in common.RUNNERS:
        result[target] = {}
        for name in ('cargo-cyclonedx','cyclonedx'):
            checkpoint()
            tool = catalog['tools'][name]
            pin = tool['platforms'][target]
            common.require(re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/[^/\s]+/[^/\s]+',pin['url']),
                           'combined qualification tool origin invalid')
            with urllib.request.urlopen(pin['url'],timeout=60) as response:
                data = response.read(tools.MAX_ARCHIVE+1)
            common.require(0 < len(data) <= tools.MAX_ARCHIVE and hashlib.sha256(data).hexdigest() == pin['sha256'],
                           'combined qualification tool distribution bytes differ')
            result[target][name] = hashlib.sha256(tools.extract_binary(data,tool['binary'],pin['format'])).hexdigest()
    return result


def qualify(source, runtime, api, distribution):
    """Bind actual uploads to independently read committed rehearsal inputs and verify both existing semantic readers."""
    common.require(os.environ['GITHUB_REPOSITORY'] == REPOSITORY and
                   os.environ['GITHUB_REPOSITORY_ID'] == str(REPOSITORY_ID) and
                   os.environ['GITHUB_JOB'] == 'collect' and
                   os.environ['GITHUB_EVENT_NAME'] in ('pull_request','push','workflow_dispatch'),
                   'combined qualification context invalid')
    environment = {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':str(source.parent),
                   'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,'GIT_TERMINAL_PROMPT':'0'}
    source_commit = os.environ['GITHUB_SHA']
    policy.source_context(source, {'commit':source_commit}, environment)
    common.require(policy.git(runtime,['rev-parse','HEAD'],environment).decode().strip() == RUNTIME,
                   'combined qualification runtime pin differs')
    helpers = {}
    for name in (*policy.RUNTIME_INPUTS, 'pins/tools.json'):
        data = common.read_input(runtime,name)
        common.require(data == policy.git(runtime,['show',RUNTIME+':'+name],environment),
                       'combined qualification runtime bytes modified')
        if name in policy.RUNTIME_INPUTS:
            helpers[name] = identity(data)
    config = tomllib.loads(common.read_input(source,'armorer.toml').decode())
    selections = common.selections(config)
    common.require(len(selections) == 9 and {case['id'] for case in selections} ==
                   {'rehearsal-library','rehearsal-cli','rehearsal-service'}, 'combined qualification selection scope differs')
    inputs = policy.snapshot(source)
    hashes = {name:inputs[name]['sha256'] for name in ('armorer.toml','armorer.lock','Cargo.lock')}
    lock = tomllib.loads(common.read_input(source,'armorer.lock').decode())
    common.require(lock['config_sha256'] == hashes['armorer.toml'] and lock['workflows'] ==
                   {'repository':REPOSITORY,'commit':RUNTIME}, 'combined qualification lock differs')
    run_id, attempt = int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT'])
    # The new workflow ID is discovered only for this explicitly nonproduction
    # qualification. Production controllers must independently supply its ID.
    provider = api.json(f'repos/{REPOSITORY}/actions/runs/{run_id}')
    common.require(provider.get('path') == CALLER and provider.get('name') == 'Unsigned combined producer handoff rehearsal' and
                   type(provider.get('workflow_id')) is int and provider['workflow_id'] > 0,
                   'combined qualification caller identity differs')
    head, branch = os.environ['EXPECTED_HEAD'], os.environ['EXPECTED_BRANCH']
    event, ref = os.environ['GITHUB_EVENT_NAME'], os.environ['GITHUB_REF']
    build = transport.ExpectedRun(REPOSITORY,REPOSITORY_ID,head,source_commit,branch,event,CALLER,
                                  provider['workflow_id'],run_id,attempt,RUNTIME)
    policy_run = ExpectedPolicyRun(REPOSITORY,REPOSITORY_ID,head,source_commit,branch,event,ref,CALLER,
                                  provider['workflow_id'],run_id,attempt,RUNTIME)
    context = {key:value for key,value in policy_run.context().items() if key not in ('event','ref')}
    measured_tools = tool_hashes(runtime)
    items = tuple(final.PayloadExpectation(case,context,hashes,
                                          case['package'].replace('-','_') if case['profile']=='library' else case['binary'],'0.1.0',
                                          measured_tools[case['target']]) for case in selections)
    catalog, catalog_id = pins.load_catalog()
    with combined.collect_producer_handoffs(api,combined.CombinedRun(build,policy_run,True),items,inputs,helpers,
                                           {'catalog':catalog,'identity':catalog_id},ci.load_policy(source)) as (builds,policies,receipt):
        build_workflow = {'repository':REPOSITORY,'path':build.builder_path,'commit':RUNTIME}
        package_workflow = {'repository':REPOSITORY,'path':'.github/workflows/release-cli.yml','commit':RUNTIME}
        runtime_bytes = identity(common.read_input(runtime,'pins/tools.json'))
        final_inputs = {'source':{'repository':REPOSITORY,'commit':source_commit,'git_ref':ref},
                        'config_sha256':hashes['armorer.toml'],'lock_sha256':hashes['armorer.lock'],
                        'cargo_lock_sha256':hashes['Cargo.lock'],'runtime':runtime_bytes,'runtime_version':'0.1.0',
                        'run':{'id':run_id,'attempt':attempt,'workflow':package_workflow}}
        def expectation(selected):
            """Construct fixture-only assembly expectations; no accepted production runtime is claimed."""
            return final.ReleaseExpectation(final_inputs,catalog_id,build_workflow,package_workflow,selected,(runtime_bytes,))
        finals = {}
        apple_block_checked = False
        if event == "pull_request":
            final_source_gate = "unsupported-PR-ref-for-final-release-layout"
        else:
            try:
                with final.prepare_final_payloads(dict(builds),expectation(items)):
                    raise AssertionError('unsigned Apple complete set accepted')
            except common.Failure as error:
                common.require(str(error) == 'protected Apple finalization required before final payload assembly',
                               'combined qualification unexpected whole-set failure')
            supported = tuple(item for item in items if item.selection['target'] != 'aarch64-apple-darwin' or
                              item.selection['profile'] == 'library')
            selected_builds = {item.selection['artifact_id']:builds[item.selection['artifact_id']] for item in supported}
            with final.prepare_final_payloads(selected_builds,expectation(supported)) as payloads:
                finals = {}
                for item in supported:
                    key = item.selection['artifact_id']
                    name = key+('.crate' if item.selection['profile']=='library' else '.tar.gz')
                    # The assembler measures the actual unsigned input and packaged
                    # output; the handoff reader independently rehashed all leaves.
                    finals[name] = payloads.packaging(key)
            apple_block_checked = True
            final_source_gate = "separately-qualified-linux-and-library-layout"
        receipt.update(distribution=distribution, workflow_id=str(provider['workflow_id']),caller_path=CALLER,
                       head_branch=branch,event=event, workflow_id_discovery='authenticated-provider-qualification-only',
                       complete_nine_selection_set_blocks_unsigned_apple=apple_block_checked,
                       final_payload_source_gate=final_source_gate,
                       separately_qualified_linux_and_library_final_payloads=finals, own_complete_signed_positive=False,
                       live_oidc_requested=False, artifact_executed=False,
                       qualification_sources={name:identity((Path(__file__).resolve().parent.parent/name).read_bytes())
                           for name in ('armorer_runtime/combined_handoff_v1.py','tests/combined_handoff_cases_v1.py',
                                        'armorer_runtime/final_payload_v1.py','armorer_runtime/policy_v1.py',
                                        'armorer_runtime/transport_v1.py')})
        checkpoint()
    common.require(policy.snapshot(source) == inputs, 'combined qualification source changed during reads')
    policy.source_context(source,{'commit':source_commit},environment)
    return receipt


def main():
    """Consume only an ephemeral read token and emit a bounded credential-free qualification receipt."""
    previous = signal.signal(signal.SIGTERM,cancel)
    try:
        common.require(len(sys.argv) == 3, 'combined qualification arguments invalid')
        source, runtime = (Path(value).resolve(strict=True) for value in sys.argv[1:])
        token = os.environ.pop('ARMORER_WORKFLOW_READ_TOKEN',None)
        with tempfile.TemporaryDirectory(prefix='armorer-combined-native-') as temporary:
            executable,distribution = install_gh(Path(temporary)/'native')
            api = transport.QualifiedGhApi(executable,token)
            _apis.append(api)
            del token
            result = qualify(source,runtime,api,distribution)
            encoded = policy.canonical(result)
            common.require(0 < len(encoded) <= 4*1024*1024, 'combined qualification output exceeds bound')
            checkpoint()
            sys.stdout.buffer.write(encoded)
    except Exception:
        sys.stderr.write('combined-native-qualification-failed\n')
        raise SystemExit(1) from None
    finally:
        _apis.clear()
        signal.signal(signal.SIGTERM,previous)


if __name__ == '__main__':
    main()
