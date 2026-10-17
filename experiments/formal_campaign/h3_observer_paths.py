"""Precisely create new private directories under inherited-SGID evidence roots.

Only a directory created by this call is fchmod'd through its own verified fd.
Existing external ancestors are never chmod'd. Symlink components fail closed.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


def _same(left, right):
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def create_private_directory(path, *, parents=False):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or path == Path("/"):
        raise ValueError("absolute non-root private directory required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    current = Path("/")
    try:
        for index, part in enumerate(path.parts[1:]):
            leaf = index == len(path.parts) - 2
            current = current / part
            created = False
            try:
                named = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                if not leaf and not parents:
                    raise
                os.mkdir(part, 0o700, dir_fd=descriptor)
                created = True
                named = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            else:
                if leaf:
                    raise FileExistsError(
                        "new private directory already exists: " + str(path)
                    )
            if not stat.S_ISDIR(named.st_mode):
                raise ValueError("symlink or non-directory path component")
            opened = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            try:
                actual = os.fstat(opened)
                if not _same(named, actual) or not stat.S_ISDIR(actual.st_mode):
                    raise ValueError("new directory inode changed")
                if created:
                    if actual.st_uid != os.getuid():
                        raise ValueError(
                            "new directory is not owned by this process uid"
                        )
                    # mkdir700 under parent2770 may produce2700. This changes
                    # only the newly-created, owned, same-inode directory fd.
                    os.fchmod(opened, 0o700)
                    fresh = os.fstat(opened)
                    entry = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                    absolute = os.lstat(current)
                    if (
                        not _same(actual, fresh)
                        or not _same(fresh, entry)
                        or not _same(fresh, absolute)
                        or fresh.st_uid != os.getuid()
                        or not stat.S_ISDIR(entry.st_mode)
                        or stat.S_IMODE(fresh.st_mode) != 0o700
                        or stat.S_IMODE(entry.st_mode) != 0o700
                    ):
                        raise ValueError("new private directory identity/mode changed")
                os.close(descriptor)
                descriptor = opened
                opened = None
            finally:
                if opened is not None:
                    os.close(opened)
        final = os.fstat(descriptor)
        named = os.lstat(path)
        if (
            not _same(final, named)
            or not stat.S_ISDIR(named.st_mode)
            or final.st_uid != os.getuid()
            or stat.S_IMODE(final.st_mode) != 0o700
        ):
            raise ValueError("new private directory final identity differs")
        return path
    finally:
        os.close(descriptor)


def require_or_create_private_directory(path):
    """Retain existing owned700 directories verbatim; create missing parents."""
    path = Path(path)
    try:
        entry = os.lstat(path)
    except FileNotFoundError:
        return create_private_directory(path, parents=True)
    if (
        not path.is_absolute()
        or path.resolve() != path
        or not stat.S_ISDIR(entry.st_mode)
        or entry.st_uid != os.getuid()
        or stat.S_IMODE(entry.st_mode) != 0o700
    ):
        raise ValueError(
            "existing private directory must already be owned/non-symlink700"
        )
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if not _same(entry, os.fstat(descriptor)) or not _same(entry, os.lstat(path)):
            raise ValueError("existing private directory inode changed")
    finally:
        os.close(descriptor)
    return path
