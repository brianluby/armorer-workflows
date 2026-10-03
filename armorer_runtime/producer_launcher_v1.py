"""Start fixed byte-qualified Node in a private sterile process; export observations, never permits.

Call this module from isolated Python in an independently trusted job/step whose
startup environment is fixed before its interpreter starts. Node-first adapters
are unsupported because a preload can steal credentials before JavaScript runs.
The proposed Node pins still require production catalog acceptance.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

from .build import parse_json
from .common import Failure, require
from .tools import platform_target
from .transport_v1 import _identity

ROOT = Path(__file__).resolve().parent
VERSION = '24.21.0'
NODE_PINS = {
    'x86_64-unknown-linux-gnu': ('linux-x64', 58088022, '6e1db87ef58b8819e5d5402eff1536491b18edd8eb7bee5ef7897876e88dc5ff',
        126595440, '7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c'),
    'aarch64-unknown-linux-gnu': ('linux-arm64', 57824078, '724282c3b43aec998aa9527380465b45d229e021b58035f5f4f63095eabfe5d5',
        122893672, '0f8949d1028f6d61506b2d5bc57e7e6fe893d7b1997509b7847294fc9c616584'),
    'aarch64-apple-darwin': ('darwin-arm64', 52909993, 'bed7eea5325e1108f32ce5228ddd6a5f0f08a499ee42aa7442aea583702f6057',
        122129232, 'e4b5a3af0e05c75de2eae013904145f40fe7fc2a6e6f17510128bf45cca4e79b'),
}
MAX_INPUT = 2 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
MAX_SECONDS = 600


def _pin():
    """Choose only the current supported native platform from immutable proposed source pins."""
    target = platform_target()
    require(target in NODE_PINS, 'producer launcher native platform unsupported')
    return NODE_PINS[target]


def prepare_node(destination: Path):
    """Credential-free preparation downloads a fixed public archive and writes only its pinned Node leaf."""
    label, size, digest, binary_size, binary_digest = _pin()
    name = f'node-v{VERSION}-{label}'
    url = f'https://nodejs.org/dist/v{VERSION}/{name}.tar.gz'
    require(not destination.is_symlink() and not destination.exists(), 'producer node destination unavailable')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=60) as response:
            require(response.geturl() == url and response.status == 200, 'producer node origin mismatch')
            data = response.read(size + 1)
        require(len(data) == size and hashlib.sha256(data).hexdigest() == digest, 'producer node distribution mismatch')
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            selected, count = [], 0
            for member in archive:
                count += 1
                require(count <= 20000, 'producer node archive bound')
                if member.name == name + '/bin/node':
                    require(member.isfile() and member.size == binary_size, 'producer node leaf mismatch')
                    stream = archive.extractfile(member)
                    require(stream is not None, 'producer node leaf unavailable')
                    with stream:
                        selected.append(stream.read(binary_size + 1))
        require(len(selected) == 1 and len(selected[0]) == binary_size and
                hashlib.sha256(selected[0]).hexdigest() == binary_digest, 'producer node byte mismatch')
        with destination.open('xb') as output:
            output.write(selected[0])
        destination.chmod(0o500)
        return destination
    except (OSError, ValueError, tarfile.TarError) as error:
        raise Failure('producer node preparation failed') from error


def _private_node(source: Path, scratch: Path):
    """Copy a no-follow, exact pinned executable into private scratch before any credential access."""
    _, _, _, size, digest = _pin()
    expected = {'size': size, 'sha256': digest}
    require(_identity(source, size) == expected, 'producer native node mismatch')
    destination = scratch / 'node'
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as input_, destination.open('xb') as output:
        remaining = size
        while remaining:
            block = input_.read(min(65536, remaining))
            require(bool(block), 'producer native node changed')
            output.write(block)
            remaining -= len(block)
        require(not input_.read(1), 'producer native node changed')
        output.flush()
        os.fsync(output.fileno())
    require(_identity(destination, size) == expected, 'producer private node mismatch')
    destination.chmod(0o500)
    return destination


def _credentials(operation, scratch):
    """Whitelist exact bounded platform credential names after validating independent inputs and Node bytes."""
    environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C.UTF-8',
        'HOME': str(scratch), 'TMPDIR': str(scratch)}
    require(operation in ('oidc', 'mapped', 'writer'), 'producer credential operation unsupported')
    names = (('ARMORER_WORKFLOW_READ_TOKEN', 'ACTIONS_RUNTIME_TOKEN') if operation == 'writer' else
        ('ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN'))
    if operation == 'mapped':
        names += ('ARMORER_WORKFLOW_READ_TOKEN',)
    for name in names:
        value = os.environ.get(name)
        require(type(value) is str and 0 < len(value) <= (16384 if name == 'ACTIONS_RUNTIME_TOKEN' else 8192) and
                not any(ord(char) <= 32 or ord(char) == 127 for char in value), 'producer credential unavailable')
        environment[name] = value
    return environment


@contextmanager
def _cancellation_state():
    """Record parent cancellation before process creation and retain cleanup ownership until all children close."""
    cancelled = [False]

    def cancel(signum, frame):
        """Mark cancellation without interrupting subprocess creation or the mandatory cleanup finally block."""
        cancelled[0] = True

    previous = signal.signal(signal.SIGTERM, cancel)
    try:
        yield cancelled
    finally:
        signal.signal(signal.SIGTERM, previous)


def _run_node(node, payload, environment, scratch, mode='producer'):
    """Run only the fixed worker with bounded pipes, closed input and cancellation-aware process cleanup."""
    with _cancellation_state() as cancelled:
        entries = {'producer': ROOT / 'producer_context_entry_v1.mjs',
            'artifact-writer': ROOT.parent / '.github/actions/qualify-artifact-writer-v1/index.mjs',
            'combined-handoff': ROOT.parent / '.github/actions/qualify-combined-handoff-v1/index.mjs'}
        require(mode in entries, 'producer startup worker unsupported')
        process = subprocess.Popen([str(node), str(entries[mode])], cwd=scratch,
            env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        deadline = time.monotonic() + (MAX_SECONDS if mode == 'producer' else 1500)
        counts, blocks = {'stdout': 0, 'stderr': 0}, []
        try:
            with selectors.DefaultSelector() as selector:
                if payload:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
                else:
                    process.stdin.close()
                selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
                selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
                sent = 0
                while selector.get_map():
                    require(not cancelled[0], 'producer launcher cancelled')
                    require(time.monotonic() < deadline, 'producer launcher timed out')
                    for key, _ in selector.select(timeout=0.1):
                        if key.data == 'stdin':
                            try:
                                sent += os.write(process.stdin.fileno(), payload[sent:sent + 65536])
                            except BlockingIOError:
                                continue
                            if sent == len(payload):
                                selector.unregister(process.stdin)
                                process.stdin.close()
                            continue
                        try:
                            block = os.read(key.fileobj.fileno(), 65536)
                        except BlockingIOError:
                            continue
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        counts[key.data] += len(block)
                        require(counts[key.data] <= (MAX_OUTPUT if key.data == 'stdout' else 1024 * 1024),
                                'producer launcher output bound')
                        if key.data == 'stdout':
                            blocks.append(block)
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            require(not cancelled[0], 'producer launcher cancelled')
            require(process.returncode == 0 and counts['stdout'] > 0, 'producer startup worker failed')
            return b''.join(blocks)
        finally:
            # Let the fixed mapped worker reap its separately owned native children first.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=90)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if not process.stdin.closed:
                process.stdin.close()
            process.stdout.close()
            process.stderr.close()


def launch_producer_context(node: Path, intent_bytes: bytes, approved_digest: str):
    """Authenticate in a fresh fixed process; serialized audit output never grants release authority."""
    require(sys.flags.isolated and sys.flags.ignore_environment and sys.flags.no_user_site,
            'producer launcher requires isolated Python startup')
    require(type(intent_bytes) is bytes and 0 < len(intent_bytes) <= MAX_INPUT and
            type(approved_digest) is str and len(approved_digest) == 64 and
            hashlib.sha256(intent_bytes).hexdigest() == approved_digest, 'producer independent intent approval mismatch')
    request = parse_json(intent_bytes)
    require(type(request) is dict and set(request) == {'schema_version', 'operation', 'intent'} and
            type(request['schema_version']) is int and request['schema_version'] == 1 and
            request['operation'] in ('oidc', 'mapped') and type(request['intent']) is dict,
            'producer independent request invalid')
    with tempfile.TemporaryDirectory(prefix='armorer-producer-startup-') as temporary:
        scratch = Path(temporary)
        scratch.chmod(0o700)
        private_node = _private_node(node, scratch)
        environment = _credentials(request['operation'], scratch)
        offered = parse_json(_run_node(private_node, intent_bytes, environment, scratch))
    require(type(offered) is dict and set(offered) == {'schema_version', 'operation', 'observation',
            'startup_environment_isolated', 'production_node_catalog_accepted', 'signing_authorized', 'publication_authorized'} and
            type(offered['schema_version']) is int and offered['schema_version'] == 1 and
            offered['operation'] == request['operation'] and type(offered['observation']) is dict and
            offered['startup_environment_isolated'] is True and offered['production_node_catalog_accepted'] is False and
            offered['signing_authorized'] is False and offered['publication_authorized'] is False,
            'producer worker observation invalid')
    return offered


def launch_native_qualification(kind: str, node: Path):
    """Run only fixed development reader shapes; no arbitrary entry, command, token or release input exists."""
    require(sys.flags.isolated and sys.flags.ignore_environment and sys.flags.no_user_site,
            'producer launcher requires isolated Python startup')
    require(kind in ('artifact-writer', 'combined-handoff'), 'native qualification unsupported')
    names = ('GITHUB_REPOSITORY', 'GITHUB_REPOSITORY_ID', 'GITHUB_JOB', 'GITHUB_EVENT_NAME',
        'GITHUB_SHA', 'GITHUB_REF', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_WORKSPACE',
        'GITHUB_STEP_SUMMARY', 'EXPECTED_HEAD', 'EXPECTED_BRANCH', 'EXPECTED_RUNNER_LABEL')
    context = {}
    for name in names:
        value = os.environ.get(name)
        require(type(value) is str and 0 < len(value) <= 4096 and
                not any(ord(char) < 32 or ord(char) == 127 for char in value), 'native qualification context unavailable')
        context[name] = value
    require(context['GITHUB_REPOSITORY'] == 'brianluby/armorer-workflows' and
        context['GITHUB_REPOSITORY_ID'] == '1398918288' and
        context['GITHUB_JOB'] == ('transport-evidence' if kind == 'artifact-writer' else 'collect'),
        'native qualification context unsupported')
    require(os.environ.get('GITHUB_SERVER_URL') == 'https://github.com' and
        os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('ACTIONS_RESULTS_URL') in
        ('https://results-receiver.actions.githubusercontent.com', 'https://results-receiver.actions.githubusercontent.com/'),
        'native qualification origin unsupported')
    with tempfile.TemporaryDirectory(prefix='armorer-reader-startup-') as temporary:
        scratch = Path(temporary)
        scratch.chmod(0o700)
        private_node = _private_node(node, scratch)
        environment = {**_credentials('writer', scratch), **context,
            'GITHUB_SERVER_URL': 'https://github.com', 'GITHUB_ACTIONS': 'true',
            'ACTIONS_RESULTS_URL': 'https://results-receiver.actions.githubusercontent.com'}
        output = _run_node(private_node, b'', environment, scratch, kind)
    offered = parse_json(output)
    require(type(offered) is dict and offered.get('signing_authorized') is False and
            offered.get('publication_authorized') is False, 'native qualification authority invalid')
    sys.stdout.buffer.write(output + b'\n')
    sys.stdout.buffer.flush()


def main():
    """Expose fixed typed request/file inputs, with no caller command, URL, key set or custom script."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', type=Path, required=True)
    parser.add_argument('--intent', type=Path, required=True)
    parser.add_argument('--approved-intent-sha256', required=True)
    arguments = parser.parse_args()
    try:
        require(arguments.intent.is_file() and not arguments.intent.is_symlink() and
                arguments.intent.stat().st_size <= MAX_INPUT, 'producer intent file invalid')
        result = launch_producer_context(arguments.node, arguments.intent.read_bytes(), arguments.approved_intent_sha256)
        print(json.dumps(result, separators=(',', ':')))
    except Exception:
        print('producer startup boundary failed', file=sys.stderr)
        raise SystemExit(1)
