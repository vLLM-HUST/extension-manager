"""Invocation-owned immutable source bytes; every reuse and exit freshly fenced.

Never caches a current runtime probe, installed payload, source observation, Git
read, environment predicate, Plan, receipt, or result from an earlier invocation.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from contextvars import ContextVar
from pathlib import Path
from threading import RLock, get_ident

_CURRENT = ContextVar("ecpa_source_read_call", default=None)
_CAPTURES = ContextVar("ecpa_source_role_observations", default=None)


def require(value, reason):
    if not value:
        raise ValueError(reason)


def _state(path):
    value = path.lstat()
    return {
        k: getattr(value, k)
        for k in (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_mode",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    }


def _ancestry(path):
    path = Path(path)
    route = {}
    for parent in (Path("/"), *reversed(path.parents[:-1])):
        info = parent.lstat()
        route[str(parent)] = dict(
            identity=[info.st_dev, info.st_ino, info.st_uid, info.st_mode],
            link=os.readlink(parent) if stat.S_ISLNK(info.st_mode) else None,
        )
    return route


def _fence(path):
    # Preserve the original reference ABI: lexical ancestors may include a link.
    # Bind each actual route component, link text, resolved target and leaf.
    # Directory clocks are excluded (normal imports create __pycache__); their
    # identities/permissions and every referenced file's full clocks remain bound.
    path = Path(path)
    route = _ancestry(path)
    require(not path.is_symlink() and path.is_file(), "source reference file changed")
    return dict(leaf=_state(path), route=route, resolved=str(path.resolve(strict=True)))


def _Git_control_fence(common, administrative, root, git):
    control = {}
    paths = []
    for directory in {common, administrative, root / ".git"}:
        if directory.is_file():
            paths.append(directory)
        else:
            for name in (
                "HEAD",
                "commondir",
                "gitdir",
                "config",
                "config.worktree",
                "packed-refs",
                "shallow",
                "info/grafts",
                "refs",
            ):
                path = directory / name
                if path.exists() or path.is_symlink():
                    paths.append(path)
                    if path.is_dir():
                        paths.extend(sorted(path.rglob("*")))
    for path in paths:
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            control[str(path)] = dict(
                identity=[info.st_dev, info.st_ino, info.st_uid, info.st_mode],
                names=sorted(child.name for child in path.iterdir()),
            )
        else:
            target = None
            if path.is_symlink():
                resolved = path.resolve(strict=True)
                require(resolved.is_file(), "Git control symlink target is not a file")
                target = dict(
                    path=str(resolved),
                    state=_state(resolved),
                    route=_ancestry(resolved),
                )
            control[str(path)] = dict(
                state=_state(path),
                route=_ancestry(path),
                link=os.readlink(path) if path.is_symlink() else None,
                target=target,
            )
    # Config may contain credentials: bind hashes only, never serialize its values.
    config = git(root, "config", "--show-origin", "--null", "--list")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.startswith("GIT_") or key in {"HOME", "XDG_CONFIG_HOME"}
    }
    return dict(
        files=control,
        resolved_config_sha256=hashlib.sha256(config).hexdigest(),
        environment_sha256=hashlib.sha256(
            json.dumps(environment, sort_keys=True).encode()
        ).hexdigest(),
    )


def _repository_fence(root, revision, git):
    root = Path(root)
    identities = (
        git(root, "rev-parse", "HEAD", revision + "^{tree}").decode().splitlines()
    )
    require(len(identities) == 2, "ambiguous actual source Git identities")
    head, tree = identities
    status = git(
        root, "--no-optional-locks", "status", "--porcelain", "--untracked-files=all"
    ).decode()
    names = (
        git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
        .decode()
        .split("\0")
    )
    source_leaves = {}
    for name in sorted(set(names) - {""}):
        path = root / name
        info = path.lstat()
        source_leaves[name] = dict(
            state=_state(path),
            route=_ancestry(path),
            resolved_parent=str(path.parent.resolve(strict=True)),
            link=os.readlink(path) if stat.S_ISLNK(info.st_mode) else None,
        )
    locations = (
        git(root, "rev-parse", "--git-common-dir", "--git-dir").decode().splitlines()
    )
    require(len(locations) == 2, "ambiguous actual Git storage roots")
    common, administrative = (Path(value) for value in locations)
    if not common.is_absolute():
        common = root / common
    if not administrative.is_absolute():
        administrative = root / administrative
    object_roots, objects = set(), {}

    def visit(directory):
        directory = directory.resolve(strict=True)
        if str(directory) in object_roots:
            return
        object_roots.add(str(directory))
        for path in (directory, *sorted(directory.rglob("*"))):
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode), "Git object storage contains link")
            if path.is_dir():
                objects[str(path)] = dict(
                    identity=[info.st_dev, info.st_ino, info.st_uid, info.st_mode],
                    names=sorted(child.name for child in path.iterdir()),
                )
            else:
                objects[str(path)] = dict(state=_state(path))
        alternates = directory / "info/alternates"
        if alternates.exists():
            for entry in alternates.read_text().splitlines():
                if entry:
                    target = Path(entry)
                    visit(target if target.is_absolute() else directory / target)

    visit(common / "objects")
    return dict(
        head=head,
        tree=tree,
        status=status,
        sources=source_leaves,
        Git_objects=objects,
        object_roots=sorted(object_roots),
        controls=_Git_control_fence(
            common.resolve(strict=True), administrative.resolve(strict=True), root, git
        ),
    )


def current():
    scope = _CURRENT.get()
    if scope is not None:
        scope.require_active()
    return scope


class fresh_source_read_call:
    """One owner plus explicitly joined source-role workers; no caller seed data."""

    def __init__(self):
        self.pid = os.getpid()
        self.owner = get_ident()
        self.lock = RLock()
        self.active = False
        self.workers = set()
        self.refs = {}
        self.raws = {}
        self.elf_inventory = {}
        self.roles = {}
        self.context_token = None

    def require_active(self):
        # Never acquire a lock inherited across fork or borrowed by a stranger.
        require(os.getpid() == self.pid, "source call crossed process")
        require(
            get_ident() == self.owner or get_ident() in self.workers,
            "source call crossed unissued thread",
        )
        require(self.active, "source call is closed")

    def __enter__(self):
        require(
            os.getpid() == self.pid and get_ident() == self.owner,
            "source scope entered outside owner",
        )
        require(
            not self.active and self.context_token is None and current() is None,
            "source call nested or reused",
        )
        self.active = True
        self.context_token = _CURRENT.set(self)
        return self

    def check_refs(self):
        self.require_active()
        with self.lock:
            for path, (_, snapshot) in self.refs.values():
                require(
                    _fence(path) == snapshot,
                    "source call reference or ancestor changed",
                )

    def check(self):
        self.check_refs()
        with self.lock:
            for root, revision, git, _, snapshot in self.roles.values():
                require(
                    _repository_fence(root, revision, git) == snapshot,
                    "source Git/checkout envelope changed",
                )

    def read(self, ref):
        self.require_active()
        path = Path(ref["path"])
        require(path.is_absolute(), "absolute source reference required")
        expected = ref["sha256"].removeprefix("sha256:")
        key = (str(path), expected)
        with self.lock:
            self.require_active()
            if key not in self.refs:
                before = _fence(path)
                raw = path.read_bytes()
                require(
                    hashlib.sha256(raw).hexdigest() == expected,
                    "runtime proof bytes changed: " + str(path),
                )
                require(_fence(path) == before, "source changed during first full read")
                self.refs[key] = (path, (raw, before))
                self.raws[id(raw)] = raw
            path, (raw, snapshot) = self.refs[key]
            require(
                _fence(path) == snapshot, "source call reference or ancestor changed"
            )
            return raw

    def source_role(self, key, root, revision, git, observe):
        self.require_active()
        key = json.dumps(key, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self.lock:
            entry = self.roles.get(key)
        if entry is not None:
            _, _, _, raw, snapshot = entry
            require(
                _repository_fence(root, revision, git) == snapshot,
                "source Git/checkout envelope changed",
            )
            captures = _CAPTURES.get()
            if captures is not None:
                captures.append((key, entry, True))
            return json.loads(raw)
        before = _repository_fence(root, revision, git)
        result = observe()
        after = _repository_fence(root, revision, git)
        require(
            before["head"] == after["head"]
            and before["tree"] == after["tree"]
            and before["status"] == after["status"]
            and before["sources"] == after["sources"]
            and before["controls"] == after["controls"],
            "source checkout changed during original complete role proof",
        )
        # A legitimate blobless Git fetch can add objects during the first full
        # proof. Keep that actual result, but do not memoize an unstable envelope.
        if before == after:
            raw = json.dumps(
                result, sort_keys=True, separators=(",", ":"), allow_nan=False
            )
            entry = (root, revision, git, raw, after)
            captures = _CAPTURES.get()
            if captures is not None:
                captures.append((key, entry, True))
            else:
                require(
                    get_ident() == self.owner, "source role published outside owner"
                )
                with self.lock:
                    require(key not in self.roles, "duplicate concurrent source role")
                    self.roles[key] = entry
        elif _CAPTURES.get() is not None:
            # First blobless fetch: actual complete proof may be returned, but
            # its unstable object envelope is explicitly not admitted to cache.
            _CAPTURES.get().append(
                (
                    key,
                    (
                        root,
                        revision,
                        git,
                        json.dumps(
                            result,
                            sort_keys=True,
                            separators=(",", ":"),
                            allow_nan=False,
                        ),
                        after,
                    ),
                    False,
                )
            )
        return result

    def accept_roles(self, observations):
        require(
            os.getpid() == self.pid and get_ident() == self.owner,
            "source observations accepted outside owner",
        )
        self.require_active()
        require(not self.workers, "source workers not joined before merge")
        merged = dict(self.roles)
        values = []
        validated = set()
        for observation in observations:
            require(
                type(observation) is _RoleObservation
                and observation.scope is self
                and len(observation.captures) == 1,
                "unissued or incomplete source role observation",
            )
            key, entry, cacheable = observation.captures[0]
            require(
                json.loads(entry[3]) == observation.value,
                "actual source role result changed before owner merge",
            )
            require(
                _repository_fence(entry[0], entry[1], entry[2]) == entry[4],
                "source Git/checkout envelope changed before owner merge",
            )
            validated.add(key)
            if cacheable:
                require(
                    key not in merged or merged[key] == entry,
                    "conflicting source role envelope",
                )
                merged[key] = entry
            values.append(observation.value)
        # All role workers have joined. Validate the entire current envelope
        # before either installing expected facts or returning any phase result.
        self.check_refs()
        for key, (root, revision, git, _, snapshot) in merged.items():
            if key in validated:
                continue
            require(
                _repository_fence(root, revision, git) == snapshot,
                "source Git/checkout envelope changed before owner merge",
            )
        self.roles = merged
        return values

    def elves(self, raw, observe):
        self.require_active()
        if self.raws.get(id(raw)) is not raw:
            return observe(raw)
        with self.lock:
            if id(raw) not in self.elf_inventory:
                self.elf_inventory[id(raw)] = json.dumps(observe(raw), sort_keys=True)
            # Never hand a mutable cached map to a caller.
            return json.loads(self.elf_inventory[id(raw)])

    def __exit__(self, kind, value, traceback):
        require(
            os.getpid() == self.pid and get_ident() == self.owner,
            "source call close outside owner",
        )
        try:
            require(not self.workers, "source workers not joined before close")
            self.check()
        finally:
            self.active = False
            _CURRENT.reset(self.context_token)
            self.refs.clear()
            self.raws.clear()
            self.elf_inventory.clear()
            self.roles.clear()
        return False


class _RoleObservation:
    __slots__ = ("scope", "value", "captures")

    def __init__(self, scope, value, captures):
        self.scope, self.value, self.captures = scope, value, tuple(captures)


def run_source_role(scope, operation, *args):
    if scope is None:
        return operation(*args)
    require(os.getpid() == scope.pid and scope.active, "source role scope unavailable")
    thread = get_ident()
    with scope.lock:
        require(thread not in scope.workers, "source role thread already borrowed")
        scope.workers.add(thread)
    token = _CURRENT.set(scope)
    capture_token = _CAPTURES.set([])
    try:
        value = operation(*args)
        return _RoleObservation(scope, value, _CAPTURES.get())
    finally:
        _CAPTURES.reset(capture_token)
        _CURRENT.reset(token)
        with scope.lock:
            scope.workers.remove(thread)


def source_read_barrier():
    scope = current()
    if scope is not None:
        scope.check()
