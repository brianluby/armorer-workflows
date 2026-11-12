"""Fixed deployment-binding contract for the release controller; no credential values or live writes.

The pinned controller workflow creates one deployment bound to its exact run/attempt before any
publication write. This module only constructs and validates that contract; the workflow performs
the fixed ``gh api`` writes with the job's ephemeral token. The payload keys mirror the native Rust
adapter's attempt binding exactly, so both sides agree on what binds an approval to an attempt.
"""
from __future__ import annotations

import re

from .common import Failure, require

ENVIRONMENT = "release-publish"
PAYLOAD_KEYS = ("armorer_run_id", "armorer_run_attempt", "armorer_source_commit")


def _route(endpoint):
    """Admit only the two fixed controller deployment write routes; no arbitrary origin or path."""
    return type(endpoint) is str and re.fullmatch(
        r"repos/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}"
        r"/deployments(?:/[1-9][0-9]*/statuses)?", endpoint) is not None


def _id(value):
    """Accept positive numeric provider IDs without booleans, floats or string coercion."""
    return type(value) is int and 0 < value <= 2**63 - 1


def deployment_payload(run_id, run_attempt, source_commit):
    """Bind the exact attempt identity; the workflow's own run context supplies these, never a record."""
    require(_id(run_id) and _id(run_attempt), "invalid controller run identity")
    require(type(source_commit) is str and re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None,
            "invalid controller source commit")
    return {"armorer_run_id": run_id, "armorer_run_attempt": run_attempt,
            "armorer_source_commit": source_commit}


def binds_attempt(payload, run_id, run_attempt, source_commit):
    """Mirror the native adapter's exact binding; a foreign run, attempt or commit never matches."""
    return (type(payload) is dict and set(payload) == set(PAYLOAD_KEYS)
            and _id(payload["armorer_run_id"]) and payload["armorer_run_id"] == run_id
            and _id(payload["armorer_run_attempt"]) and payload["armorer_run_attempt"] == run_attempt
            and type(payload["armorer_source_commit"]) is str
            and payload["armorer_source_commit"] == source_commit)


def create_deployment_body(run_id, run_attempt, source_commit, environment=ENVIRONMENT):
    """Build the create-deployment body. auto_merge is false so the exact frozen commit is never
    merged with the default branch (which would change the sha and break the binding);
    required_contexts is empty because commit-status checks are not the publication gate — the
    environment's required reviewers and the adapter's gate observation are the authority."""
    require(environment == ENVIRONMENT, "unsupported controller environment")
    return {"ref": source_commit, "task": "deploy", "auto_merge": False, "required_contexts": [],
            "environment": environment, "description": "Armorer release controller attempt binding",
            "transient_environment": False, "production_environment": False,
            "payload": deployment_payload(run_id, run_attempt, source_commit)}


def active_status_body():
    """Mark the deployment active (non-terminal) so the adapter observes it holding the environment."""
    return {"state": "in_progress", "description": "Armorer release controller active"}


def deployment_route(repository):
    route = f"repos/{repository}/deployments"
    require(_route(route), "unsupported controller deployment route")
    return route


def status_route(repository, deployment_id):
    require(_id(deployment_id), "invalid controller deployment id")
    route = f"repos/{repository}/deployments/{deployment_id}/statuses"
    require(_route(route), "unsupported controller deployment route")
    return route