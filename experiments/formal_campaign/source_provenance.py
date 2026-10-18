"""Explicit new full-tuple source policy. Local-only commits cannot self-admit."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

POLICY = "ecpa-full-tuple-source-provenance-policy/v1"
OBSERVATION = "ecpa-full-tuple-source-provenance-observation/v1"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MANAGER = "vLLM-HUST/extension-manager"
HOST = "vLLM-HUST/vllm-hust"
H4_SOURCE_OWNED_FILES = {
    "h4_pair_activation.py",
    "h4_owned_resources.py",
    "h4_source_owned_intake.py",
    "h4_npu_observation.py",
    "h4-launch-spec.schema.json",
    "h3_runtime_source_closure.py",
    "h3_dynamic_host.py",
}


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def subjects(fixed):
    plugins = fixed.get("plugin_commits")
    if plugins is None:
        plugins = {name: item["commit"] for name, item in fixed["plugins"].items()}
    require(
        isinstance(plugins, dict) and plugins, "full tuple plugin identities missing"
    )
    result = {
        "manager": fixed["manager_commit"],
        "host": fixed["host_commit"],
        "accelerator": fixed["accelerator_commit"],
    }
    result.update({"plugin:" + name: commit for name, commit in plugins.items()})
    require(
        all(isinstance(v, str) and COMMIT.fullmatch(v) for v in result.values()),
        "full tuple requires exact concrete commits",
    )
    return result


def validate_policy(policy, fixed):
    expected = subjects(fixed)
    require(
        set(policy) == {"schema", "components"}
        and policy["schema"] == POLICY
        and isinstance(policy["components"], dict)
        and set(policy["components"]) == set(expected),
        "new full tuple source policy must declare every exact component",
    )
    for role, definition in policy["components"].items():
        require(
            set(definition) == {"repository", "requirement"}
            and isinstance(definition["repository"], str)
            and REPOSITORY.fullmatch(definition["repository"])
            and definition["requirement"] in {"published-commit", "merged-main"},
            "source policy requirement unsupported; no implicit source proof",
        )
        if role in {"manager", "host"}:
            require(
                definition
                == {
                    "repository": MANAGER if role == "manager" else HOST,
                    "requirement": "merged-main",
                },
                "original Manager/Host merged-main policy cannot be weakened",
            )
    return expected


GIT_FETCH_ATTEMPTS = 3
GIT_FETCH_TIMEOUT_SECONDS = 300


def _transport_diagnostic(value):
    # Independent diagnostic channel, never part of the source observation or
    # any validity cache. Raw output is losslessly preserved, including bytes
    # that are not UTF-8, in the caller's existing stderr evidence stream.
    sys.stderr.write(json.dumps(value, sort_keys=True) + "\n")
    sys.stderr.flush()


class GitFetchTransportError(subprocess.CalledProcessError):
    """A failed bounded fetch with original outputs retained for outer callers."""

    def __init__(self, command, error, *, timed_out):
        super().__init__(
            124 if timed_out else error.returncode,
            command,
            output=error.stdout or b"",
            stderr=error.stderr or b"",
        )
        self.timed_out = timed_out

    def __str__(self):
        summary = (
            f"Git fetch timed out after {GIT_FETCH_TIMEOUT_SECONDS}s "
            "(Git exit code not observed)"
            if self.timed_out
            else super().__str__()
        )
        return (
            summary
            + "\nGit fetch stdout:\n"
            + self.stdout.decode("utf-8", errors="backslashreplace")
            + "\nGit fetch stderr:\n"
            + self.stderr.decode("utf-8", errors="backslashreplace")
        )


def _git(repo, *args):
    command = ["git", "-C", str(repo), *args]
    if not args or args[0] != "fetch":
        return subprocess.run(command, check=True, capture_output=True).stdout
    started = time.monotonic_ns()
    error = None
    timed_out = False
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            timeout=GIT_FETCH_TIMEOUT_SECONDS,
        )
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        error = exc
        timed_out = isinstance(exc, subprocess.TimeoutExpired)
        stdout, stderr = exc.stdout or b"", exc.stderr or b""
        returncode = None if timed_out else exc.returncode
    _transport_diagnostic(
        {
            "schema": "ecpa-canonical-git-fetch-attempt/v1",
            "event": "fetch-command-result",
            "command": command,
            "clock": "CLOCK_MONOTONIC",
            "started_ns": started,
            "finished_ns": time.monotonic_ns(),
            "timeout_seconds": GIT_FETCH_TIMEOUT_SECONDS,
            "timed_out": timed_out,
            "returncode": returncode,
            "stdout_base64": base64.b64encode(stdout).decode("ascii"),
            "stderr_base64": base64.b64encode(stderr).decode("ascii"),
            "source_admission": False,
        }
    )
    if error is not None:
        raise GitFetchTransportError(command, error, timed_out=timed_out) from error
    return stdout


def _observe_remote_component(role, url, commit, definition):
    # Only fetch transport failures retry. Each attempt uses a new empty object
    # store, including re-fetching the exact commit if a later main fetch fails.
    # All SHA/tree/ancestry predicates must pass in the same successful attempt.
    # Neither predicate consumes file blobs. Fetch all commits/trees, excluding
    # only blobs: no shallow boundary, alternate object store or prior admission.
    for attempt in range(1, GIT_FETCH_ATTEMPTS + 1):
        with tempfile.TemporaryDirectory(prefix="ecpa-source-fetch-") as temporary:
            quarantine = Path(temporary)
            _transport_diagnostic(
                {
                    "schema": "ecpa-canonical-git-fetch-attempt/v1",
                    "event": "component-attempt-begin",
                    "role": role,
                    "requested_commit": commit,
                    "remote": url,
                    "quarantine": str(quarantine),
                    "attempt": attempt,
                    "attempt_limit": GIT_FETCH_ATTEMPTS,
                    "source_admission": False,
                }
            )
            try:
                _git(quarantine, "init", "--bare", "--quiet")
                _git(quarantine, "remote", "add", "source", url)
                require(
                    _git(quarantine, "remote", "get-url", "source").decode().strip()
                    == url,
                    "quarantine Git transport rewrites declared canonical remote",
                )
                _git(
                    quarantine,
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--filter=blob:none",
                    url,
                    commit,
                )
                fetched = _git(quarantine, "rev-parse", "FETCH_HEAD").decode().strip()
                require(
                    fetched == commit, "remote did not serve requested exact source"
                )
                remote_tree = (
                    _git(quarantine, "rev-parse", commit + "^{tree}").decode().strip()
                )
                main = None
                if definition["requirement"] == "merged-main":
                    _git(
                        quarantine,
                        "fetch",
                        "--quiet",
                        "--no-tags",
                        "--filter=blob:none",
                        url,
                        "refs/heads/main",
                    )
                    main = _git(quarantine, "rev-parse", "FETCH_HEAD").decode().strip()
                    merged = (
                        subprocess.run(
                            [
                                "git",
                                "-C",
                                str(quarantine),
                                "merge-base",
                                "--is-ancestor",
                                commit,
                                main,
                            ],
                            check=False,
                            capture_output=True,
                        ).returncode
                        == 0
                    )
                    require(
                        merged,
                        "requested component commit is not merged to remote main",
                    )
            except GitFetchTransportError:
                if attempt == GIT_FETCH_ATTEMPTS:
                    raise
                continue
            return fetched, remote_tree, main
    raise AssertionError("bounded fetch attempts did not return or raise")


def repository_name(remote):
    # This policy's repository identity is a GitHub owner/repository, not an
    # arbitrary URL path or a local mirror that happens to contain a commit.
    require(isinstance(remote, str), "source remote URL missing")
    if remote.startswith("git@github.com:"):
        path = remote.removeprefix("git@github.com:")
    else:
        parsed = urlparse(remote)
        require(
            parsed.hostname == "github.com"
            and parsed.scheme in {"https", "ssh"}
            and parsed.port in {None, 443, 22},
            "source remote is not declared GitHub repository",
        )
        path = parsed.path.strip("/")
    name = path.removesuffix(".git")
    require(REPOSITORY.fullmatch(name), "source remote repository identity invalid")
    return name


def observe_component(role, commit, definition, location):
    """Fetch the requested actual remote commit and inspect clean exact source."""
    require(set(location) == {"path", "remote"}, "source location fields differ")
    repo = Path(location["path"])
    require(repo.is_absolute() and repo.is_dir(), "source checkout unavailable")
    remote = location["remote"]
    require(
        isinstance(remote, str) and remote and not remote.startswith("-"),
        "source remote alias invalid",
    )
    url = _git(repo, "remote", "get-url", remote).decode().strip()
    require(
        repository_name(url) == definition["repository"],
        "source remote repository differs",
    )
    fetched, remote_tree, main = _observe_remote_component(
        role, url, commit, definition
    )
    require(
        _git(repo, "rev-parse", "HEAD").decode().strip() == commit,
        "clean source checkout is not requested component commit",
    )
    require(
        not _git(repo, "status", "--porcelain"), "component source checkout is dirty"
    )
    tree = _git(repo, "rev-parse", commit + "^{tree}").decode().strip()
    require(tree == remote_tree, "checkout source tree differs from remote bytes")
    # Recheck tracked/untracked state after remote/tree observations; source
    # mutation must not be hidden behind a former clean HEAD observation.
    require(
        _git(repo, "rev-parse", "HEAD").decode().strip() == commit
        and not _git(repo, "status", "--porcelain"),
        "component source changed during observation",
    )
    return dict(
        role=role,
        repository=definition["repository"],
        remote=url,
        requested_commit=commit,
        remote_commit=fetched,
        tree=tree,
        clean_checkout=True,
        requirement=definition["requirement"],
        main_commit=main,
        merged_to_main=True if main is not None else None,
    )


def observe_sources(fixed, policy, repositories):
    expected = validate_policy(policy, fixed)
    require(
        set(repositories) == set(expected),
        "source locations must cover full tuple exactly",
    )
    observations = {
        role: observe_component(
            role, commit, policy["components"][role], repositories[role]
        )
        for role, commit in expected.items()
    }
    result = dict(
        schema=OBSERVATION,
        policy_sha256=digest(canonical(policy)),
        subjects=expected,
        components=observations,
        identity_verified=True,
    )
    validate_observation(result, policy, fixed)
    return result


def validate_observation(observation, policy, fixed):
    expected = validate_policy(policy, fixed)
    require(
        set(observation)
        == {"schema", "policy_sha256", "subjects", "components", "identity_verified"}
        and observation["schema"] == OBSERVATION
        and observation["policy_sha256"] == digest(canonical(policy))
        and observation["subjects"] == expected
        and observation["identity_verified"] is True
        and set(observation["components"]) == set(expected),
        "full tuple source observation is missing or mismatched",
    )
    for role, commit in expected.items():
        value = observation["components"][role]
        definition = policy["components"][role]
        require(
            set(value)
            == {
                "role",
                "repository",
                "remote",
                "requested_commit",
                "remote_commit",
                "tree",
                "clean_checkout",
                "requirement",
                "main_commit",
                "merged_to_main",
            }
            and value["role"] == role
            and value["repository"] == definition["repository"]
            and repository_name(value["remote"]) == definition["repository"]
            and value["requested_commit"] == value["remote_commit"] == commit
            and COMMIT.fullmatch(value["tree"])
            and value["clean_checkout"] is True
            and value["requirement"] == definition["requirement"],
            "component requested/source identity differs",
        )
        if definition["requirement"] == "merged-main":
            require(
                isinstance(value["main_commit"], str)
                and COMMIT.fullmatch(value["main_commit"])
                and value["merged_to_main"] is True,
                "component merge admission is unverified",
            )
        else:
            require(
                value["main_commit"] is None and value["merged_to_main"] is None,
                "published-only source cannot claim an unobserved merge",
            )


def upgrade_receipt(receipt, campaign, observation, protocol_binding):
    """Extend a fully verified legacy transition; never upgrade historical files."""
    policy = campaign.get("source_provenance_policy")
    require(isinstance(policy, dict), "new issuance needs a preregistered policy")
    validate_observation(observation, policy, campaign["fixed_identity"])
    versions = {
        "ecpa-h3-deployment-receipt/v2": "ecpa-h3-deployment-receipt/v3",
        "ecpa-h4-deployment-receipt/v1": "ecpa-h4-deployment-receipt/v2",
    }
    require(receipt.get("schema") in versions, "unknown base transition")
    result = dict(
        receipt,
        schema=versions[receipt["schema"]],
        source_provenance_policy=policy,
        source_provenance_observation=observation,
        source_provenance_protocol_binding=protocol_binding,
    )
    validate_protocol_binding(
        protocol_binding, "h3" if "/v3" in result["schema"] else "h4"
    )
    # The new observation must cover exactly the already-issued deployment.
    require(
        subjects(result) == subjects(campaign["fixed_identity"]),
        "receipt full tuple differs from source observation",
    )
    return result


def receipt_schema(receipt, campaign, family):
    """Select frozen legacy format or explicit prospectively declared policy."""
    old = 2 if family == "h3" else 1
    new = old + 1
    require(family in {"h3", "h4"}, "unknown campaign family")
    version = receipt.get("schema")
    policy = campaign.get("source_provenance_policy")
    if version == f"ecpa-{family}-deployment-receipt/v{new}":
        require(
            isinstance(policy, dict)
            and receipt.get("source_provenance_policy") == policy,
            "receipt is not bound to prospectively declared source policy",
        )
        validate_protocol_binding(
            receipt.get("source_provenance_protocol_binding"), family
        )
        validate_observation(
            receipt.get("source_provenance_observation", {}),
            policy,
            campaign["fixed_identity"],
        )
        require(
            subjects(receipt) == subjects(campaign["fixed_identity"]),
            "receipt component identities differ",
        )
        return f"{family}-deployment-receipt-v{new}.schema.json"
    require(
        policy is None and version == f"ecpa-{family}-deployment-receipt/v{old}",
        "new source policy cannot consume a legacy unverified tuple receipt",
    )
    return f"{family}-deployment-receipt.schema.json"


def bind_protocol_source(
    manager_repo, manager_commit, family, *, h4_source_owned=False
):
    """The new helper/schema must be bytes in the admitted Manager source."""
    version = 3 if family == "h3" else 2
    result = {}
    names = {
        "source_provenance.py",
        f"{family}_registration.py",
        f"{family}-deployment-receipt-v{version}.schema.json",
    }
    if h4_source_owned:
        require(family == "h4", "H4 activation source domain cannot replace H3")
        names |= H4_SOURCE_OWNED_FILES
    for name in sorted(names):
        relative = "experiments/formal_campaign/" + name
        raw = _git(manager_repo, "show", manager_commit + ":" + relative)
        require(
            raw == (Path(__file__).parent / name).read_bytes(),
            "new source provenance implementation is outside admitted Manager source",
        )
        result[name] = digest(raw)
    return result


def validate_protocol_binding(binding, family):
    version = 3 if family == "h3" else 2
    names = {
        "source_provenance.py",
        f"{family}_registration.py",
        f"{family}-deployment-receipt-v{version}.schema.json",
    }
    require(isinstance(binding, dict), "source binding must be an object")
    if family == "h4" and set(binding) == names | H4_SOURCE_OWNED_FILES:
        names |= H4_SOURCE_OWNED_FILES
    require(
        set(binding) == names,
        "new source provenance protocol binding incomplete",
    )
    require(
        all(
            binding[name] == digest((Path(__file__).parent / name).read_bytes())
            for name in names
        ),
        "new source provenance protocol source differs",
    )
