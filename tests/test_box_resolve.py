"""Compare box path walking with Linux path walking in an isolated root."""

import json
import os
import shutil
import subprocess
import sys
from functools import lru_cache

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from rubberbandbox import box


pytestmark = pytest.mark.skipif(shutil.which("bwrap") is None, reason="bwrap is required")
NAMES = tuple("abcd")


@st.composite
def trees_and_queries(draw):
    entries = []
    directories = [()]
    occupied = set()
    budget = draw(st.integers(min_value=0, max_value=12))
    while len(entries) < budget:
        slots = [parent + (name,) for parent in directories if len(parent) < 3
                 for name in NAMES if parent + (name,) not in occupied]
        if not slots:
            break
        path = draw(st.sampled_from(slots))
        kind = draw(st.sampled_from(("directory", "file", "link", "self", "mutual")))
        if kind == "directory":
            directories.append(path)
            target = None
        elif kind == "file":
            target = None
        elif kind == "self":
            kind, target = "link", path[-1]
        elif kind == "mutual":
            peers = [p for p in slots if p[:-1] == path[:-1] and p != path]
            if peers and len(entries) + 2 <= budget:
                peer = draw(st.sampled_from(peers))
                entries.append((peer, "link", path[-1]))
                occupied.add(peer)
                target = peer[-1]
            else:
                target = path[-1]
            kind = "link"
        else:
            parts = draw(st.lists(st.sampled_from((*NAMES, ".", "..")), min_size=1, max_size=3))
            target = ("/" if draw(st.booleans()) else "") + "/".join(parts)
        entries.append((path, kind, target))
        occupied.add(path)

    query = st.builds(
        lambda parts, trailing: "/" + "/".join(parts) + ("/" if trailing else ""),
        st.lists(st.sampled_from((*NAMES, ".", "..", "")), max_size=6),
        st.booleans(),
    )
    queries = draw(st.lists(query, min_size=1, max_size=20))
    return entries, queries


ORACLE = r'''
import json
import os
import stat
import sys


def opened(path):
    fd = os.open(path, os.O_PATH)
    try:
        return os.readlink(f"/proc/self/fd/{fd}"), stat.S_ISDIR(os.fstat(fd).st_mode)
    finally:
        os.close(fd)


def resolve(query, depth=0):
    if depth > 40:
        return "REJECT"
    try:
        return opened(query)[0]
    except FileNotFoundError:
        parts = [part for part in query.split("/") if part != ""]
        existing, directory = opened("/")
        for index in range(len(parts)):
            prefix = "/" + "/".join(parts[:index + 1])
            try:
                existing, directory = opened(prefix)
            except FileNotFoundError:
                if os.path.islink(prefix):  # dangling: a create would follow it, so the oracle does too
                    target, rest = os.readlink(prefix), "/".join(parts[index + 1:])
                    base = "" if target.startswith("/") else existing.rstrip("/")
                    return resolve(f"{base}/{target}" + (f"/{rest}" if rest else ""), depth + 1)
                remaining = parts[index:]
                if not directory or any(part in (".", "..") for part in remaining):
                    return "REJECT"
                return existing.rstrip("/") + "/" + "/".join(remaining)
            except OSError:
                return "REJECT"
        return "REJECT"
    except OSError:
        return "REJECT"


print(json.dumps([resolve(query) for query in json.loads(sys.argv[1])]))
'''


@lru_cache(maxsize=1)
def python_closure():
    executable = os.path.realpath(sys.executable)
    assert executable.startswith("/nix/store/"), executable
    root = "/".join(executable.split("/")[:4])
    result = subprocess.run(["nix-store", "-qR", root], capture_output=True,
                            text=True, check=True, timeout=60)
    paths = result.stdout.splitlines()
    assert paths and all(path.startswith("/nix/store/") for path in paths)
    return executable, paths


def python_answer(tree, query):
    try:
        return box.resolve(str(tree), query)
    except box.PathRejected:
        return "REJECT"


@settings(max_examples=60, deadline=None, database=None, suppress_health_check=[
    HealthCheck.too_slow, HealthCheck.function_scoped_fixture,
])
@given(case=trees_and_queries())
def test_resolve_matches_kernel(tmp_path, case):
    entries, queries = case
    tree = tmp_path / "tree"
    if tree.exists():
        shutil.rmtree(tree)
    tree.mkdir()
    listing = []
    for parts, kind, target in entries:
        path = tree.joinpath(*parts)
        if kind == "directory":
            path.mkdir()
        elif kind == "file":
            path.touch()
        else:
            path.symlink_to(target)
        listing.append(f"/{'/'.join(parts)}: {kind}" + (f" -> {target}" if target else ""))

    expected = [python_answer(tree, query) for query in queries]
    executable, closure = python_closure()
    args = ["bwrap", "--bind", str(tree), "/"]
    for path in closure:
        args.extend(("--ro-bind", path, path))
    args.extend(("--proc", "/proc", "--dev", "/dev", "--unshare-all",
                 "--die-with-parent", "--chdir", "/", executable, "-c", ORACLE,
                 json.dumps(queries)))
    result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    actual = json.loads(result.stdout)
    assert len(actual) == len(queries)
    for query, python, kernel in zip(queries, expected, actual):
        assert python == kernel, (f"tree:\n{chr(10).join(listing) or '(empty)'}\n"
                                  f"query={query!r}\npython={python!r}\nkernel={kernel!r}")


def test_absolute_link_is_reanchored(tmp_path):
    (tmp_path / "a").symlink_to("/etc/shadow")
    assert box.resolve(str(tmp_path), "/a") == "/etc/shadow"


def test_relative_link_uses_parent(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b").touch()
    (tmp_path / "a" / "c").symlink_to("b")
    assert box.resolve(str(tmp_path), "/a/c") == "/a/b"


def test_parent_is_clamped_at_root(tmp_path):
    (tmp_path / "a").mkdir()
    assert box.resolve(str(tmp_path), "/../../a/../../..") == "/"


def test_two_link_loop_rejects(tmp_path):
    (tmp_path / "a").symlink_to("b")
    (tmp_path / "b").symlink_to("a")
    with pytest.raises(box.PathRejected):
        box.resolve(str(tmp_path), "/a")


def test_link_limit(tmp_path):
    (tmp_path / "target").touch()
    for index in range(41):
        target = f"link{index + 1}" if index < 40 else "target"
        (tmp_path / f"link{index}").symlink_to(target)
    assert box.resolve(str(tmp_path), "/link1") == "/target"
    with pytest.raises(box.PathRejected):
        box.resolve(str(tmp_path), "/link0")


def test_missing_tail_under_file_rejects(tmp_path):
    (tmp_path / "a").touch()
    with pytest.raises(box.PathRejected):
        box.resolve(str(tmp_path), "/a/b")
