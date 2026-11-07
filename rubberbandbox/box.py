"""Local server confinement: an allowlist box (bubblewrap), staged writes (overlay), and path
canonicalisation in the box's own view of its filesystem.

Inside the box exists only: the command's Nix runtime closure (read-only), owner-listed read-only
paths, owner folders as overlays (writes staged until the owner commits), owner-listed sockets,
a minimal /dev and /proc, a private /tmp. No network, no host environment."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from typing import Iterator, Mapping

MAX_LINKS = 40
MAX_PATH = 4096
_RESERVED = ("/nix", "/proc", "/dev", "/tmp")
_WHITEOUT = (0, 0)
_OVERLAY_XATTR = "user.overlay."
# Bookkeeping that changes nothing about content. redirect/metacopy (content lives elsewhere) and
# anything unknown fail closed.
_BENIGN = frozenset({"user.overlay.opaque", "user.overlay.origin", "user.overlay.impure", "user.overlay.nlink"})


class BoxError(RuntimeError):
    pass


class PathRejected(ValueError):
    pass


def components(path: str) -> tuple[str, ...] | None:
    """Components of an absolute, lexically normal path ('/a/b'), else None."""
    if not path.startswith("/") or "\0" in path:
        return None
    if path == "/":
        return ()
    parts = tuple(path[1:].split("/"))
    return None if any(p in ("", ".", "..") for p in parts) else parts


@dataclass(frozen=True)
class Box:
    folders: Mapping[str, str] = field(default_factory=dict)  # box path -> host folder (overlay)
    ro_paths: tuple[str, ...] = ()  # extra read-only host paths, bound at the same path
    sockets: Mapping[str, str] = field(default_factory=dict)  # box path -> host unix socket
    stage: str = ""  # host dir for overlay upper/work dirs; required when folders are given

    def __post_init__(self) -> None:
        # host paths are pinned by realpath: identity names the real target, launch re-checks it
        object.__setattr__(self, "folders", {d: os.path.realpath(h) for d, h in self.folders.items()})
        object.__setattr__(self, "ro_paths", tuple(os.path.realpath(p) for p in self.ro_paths))
        object.__setattr__(self, "sockets", {d: os.path.realpath(h) for d, h in self.sockets.items()})
        for p in [*self.folders, *self.sockets]:
            if components(p) in (None, ()) or any(p == r or p.startswith(r + "/") for r in _RESERVED):
                raise BoxError(f"bad box path {p!r}")
        for p in self.ro_paths:  # named entries, never a wholesale /etc, /home or store
            parts = components(p)
            in_store = parts is not None and parts[:2] == ("nix", "store") and len(parts) > 2
            if parts is None or len(parts) < 2 or (not in_store and "/" + parts[0] in _RESERVED):
                raise BoxError(f"read-only path {p!r} must name a specific entry")
        # no mount inside another: removing one then only ever removes what it showed
        dests = [*self.folders, *self.sockets, *self.ro_paths]
        for i, a in enumerate(dests):
            for b in dests[i + 1:]:
                ca, cb = components(a), components(b)
                if ca == cb or cb[:len(ca)] == ca or ca[:len(cb)] == cb:  # type: ignore[index]
                    raise BoxError(f"box mounts overlap: {a} and {b}")
        if self.folders and not self.stage:
            raise BoxError("folders need a stage dir")

    def check_host(self) -> None:
        """At launch: the pinned host paths still are what the owner configured."""
        for h in [*self.folders.values(), *self.ro_paths, *self.sockets.values()]:
            if os.path.realpath(h) != h:
                raise BoxError(f"{h} now resolves elsewhere")
        for h in self.folders.values():
            if not os.path.isdir(h):
                raise BoxError(f"folder {h} is not a directory")
        for h in self.sockets.values():  # anything else would be a writable bind around the stage
            if not stat.S_ISSOCK(os.stat(h).st_mode):
                raise BoxError(f"{h} is not a socket")

    def identity(self) -> dict:
        """What the box exposes; part of the operator's identity (the stage dir is not)."""
        return {"folders": dict(sorted(self.folders.items())), "ro_paths": sorted(self.ro_paths),
                "sockets": dict(sorted(self.sockets.items()))}

    def layer(self, box_path: str) -> tuple[str, str]:
        d = os.path.join(self.stage, hashlib.sha256(box_path.encode()).hexdigest()[:16])
        return os.path.join(d, "upper"), os.path.join(d, "work")


def _store_root(path: str) -> str | None:
    real = os.path.realpath(path)
    parts = real.split("/")
    return "/".join(parts[:4]) if real.startswith("/nix/store/") and len(parts) >= 4 else None


def closure(paths: list[str]) -> list[str]:
    """Runtime closure of the store paths among `paths`. Fails closed: never all of /nix."""
    roots = sorted({r for r in map(_store_root, paths) if r})
    if not roots:
        raise BoxError("no Nix store path to compute a closure from")
    try:
        out = subprocess.run(["nix-store", "-qR", *roots], capture_output=True, text=True, check=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BoxError(f"cannot compute closure: {exc!r}") from None
    found = out.stdout.split()
    if not found or not all(p.startswith("/nix/store/") for p in found):
        raise BoxError("closure query returned nothing usable")
    return found


def launch_args(command: tuple[str, ...], env: Mapping[str, str], cwd: str, box: Box, info_fd: int) -> list[str]:
    box.check_host()
    exe = os.path.realpath(command[0])
    if _store_root(exe) is None:
        raise BoxError(f"{command[0]!r} is not in the Nix store; list an interpreter from the store")
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise BoxError("bubblewrap is not installed")
    args = [bwrap, "--info-fd", str(info_fd), "--unshare-all", "--unshare-user", "--disable-userns",
            "--die-with-parent", "--new-session", "--clearenv"]
    for k, v in sorted(env.items()):
        args += ["--setenv", k, v]
    bound = closure([exe, *box.ro_paths])
    for p in bound:
        args += ["--ro-bind", p, p]
    for p in box.ro_paths:
        if not any(p == b or p.startswith(b + "/") for b in bound):
            args += ["--ro-bind", p, p]
    args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for dest, host in sorted(box.folders.items()):
        upper, work = box.layer(dest)
        os.makedirs(upper, exist_ok=True)
        os.makedirs(work, exist_ok=True)
        args += ["--overlay-src", host, "--overlay", upper, work, dest]
    for dest, host in sorted(box.sockets.items()):
        args += ["--dir", os.path.dirname(dest), "--bind", host, dest]
    return [*args, "--chdir", cwd, exe, *command[1:]]


# ---- canonicalisation in the box's view: a manual RESOLVE_IN_ROOT ----

_DIR = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def resolve(root: str, path: str) -> str:
    """Canonical box path for `path`, walking under `root` (e.g. /proc/<pid>/root) one component
    at a time. The OS never follows a link: absolute targets restart at the box root, relative
    ones at the link's parent, '..' stops at the root. Missing tails are appended only below an
    existing directory and may not contain '.' or '..'. Every other surprise is a reject."""
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path or len(path) > MAX_PATH:
        raise PathRejected("not an absolute path")
    try:
        fds = [os.open(root, _DIR & ~os.O_NOFOLLOW)]
    except OSError as exc:
        raise PathRejected(f"box is gone: {exc.strerror}") from None
    names: list[str] = []
    pending = path.split("/")[::-1]
    links = 0
    try:
        while pending:
            c = pending.pop()
            if c in ("", "."):
                continue
            if c == "..":
                if names:
                    names.pop()
                    os.close(fds.pop())
                continue
            try:
                st = os.stat(c, dir_fd=fds[-1], follow_symlinks=False)
            except FileNotFoundError:
                rest = [x for x in (c, *reversed(pending)) if x != ""]
                if any(x in (".", "..") for x in rest):
                    raise PathRejected("'.' or '..' below a missing component") from None
                return "/" + "/".join(names + rest)
            if stat.S_ISLNK(st.st_mode):
                links += 1
                if links > MAX_LINKS:
                    raise PathRejected("too many links")
                target = os.readlink(c, dir_fd=fds[-1])
                if target.startswith("/"):
                    while len(fds) > 1:
                        os.close(fds.pop())
                    names.clear()
                pending.extend(target.split("/")[::-1])
            elif stat.S_ISDIR(st.st_mode):
                fds.append(os.open(c, _DIR, dir_fd=fds[-1]))
                names.append(c)
            elif pending:
                raise PathRejected(f"{'/'.join(['', *names, c])} is not a directory")
            else:
                names.append(c)
        return "/" + "/".join(names)
    except OSError as exc:
        raise PathRejected(f"cannot resolve: {exc.strerror}") from None
    finally:
        for fd in fds:
            os.close(fd)


# ---- the stage: review and commit staged writes ----


@dataclass(frozen=True)
class Staged:
    path: str  # box path
    action: str  # write | mkdir | delete | replace-dir | skip


def _walk(upper: str, prefix: str) -> Iterator[tuple[str, str, os.stat_result]]:
    for name in sorted(os.listdir(upper)):
        host, boxp = os.path.join(upper, name), f"{prefix}/{name}"
        yield host, boxp, os.lstat(host)


def _overlay_attrs(host: str) -> dict[str, bytes]:
    try:
        return {a: os.getxattr(host, a, follow_symlinks=False)
                for a in os.listxattr(host, follow_symlinks=False) if a.startswith(_OVERLAY_XATTR)}
    except OSError:
        return {}


def staged(box: Box) -> list[Staged]:
    """What the server changed, from the overlay upper dirs. Symlinks and special files are listed
    as 'skip': they are never committed to the host."""
    out: list[Staged] = []

    def walk(upper: str, prefix: str) -> None:
        for host, boxp, st in _walk(upper, prefix):
            attrs = _overlay_attrs(host)
            if stat.S_ISCHR(st.st_mode) and (os.major(st.st_rdev), os.minor(st.st_rdev)) == _WHITEOUT:
                out.append(Staged(boxp, "delete"))
            elif set(attrs) - _BENIGN:
                raise BoxError(f"{boxp}: overlay metadata {sorted(attrs)} not supported")
            elif stat.S_ISDIR(st.st_mode):
                out.append(Staged(boxp, "replace-dir" if attrs.get("user.overlay.opaque") == b"y" else "mkdir"))
                walk(host, boxp)
            elif stat.S_ISREG(st.st_mode):
                out.append(Staged(boxp, "write"))
            else:
                out.append(Staged(boxp, "skip"))

    for dest in sorted(box.folders):
        upper, _ = box.layer(dest)
        if os.path.isdir(upper):
            walk(upper, dest)
    return out


def commit(box: Box) -> list[Staged]:
    """Apply staged writes to the host folders, then clear the stage. The server must be stopped.
    Host-side links are never followed: an entry the box replaced is replaced, not written through."""
    changes = staged(box)  # validates the whole stage before touching anything
    for dest, host in sorted(box.folders.items()):
        upper, _ = box.layer(dest)
        if os.path.isdir(upper):
            fd = _open_nofollow(host)
            try:
                _apply(upper, fd)
            finally:
                os.close(fd)
    discard(box)
    return changes


def _open_nofollow(path: str) -> int:
    """A directory fd for `path`, refusing a link at every component, not just the last."""
    fd = os.open("/", os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for c in components(path) or ():
            nxt = os.open(c, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nxt
    except OSError:
        os.close(fd)
        raise BoxError(f"{path} is not a link-free directory path") from None
    return fd


def _lstat(name: str, dir_fd: int) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _remove(name: str, dir_fd: int) -> None:
    st = _lstat(name, dir_fd)
    if st is None:
        return
    if stat.S_ISDIR(st.st_mode):
        shutil.rmtree(name, dir_fd=dir_fd)
    else:
        os.unlink(name, dir_fd=dir_fd)


def _apply(upper: str, dir_fd: int) -> None:
    for host, _, st in _walk(upper, ""):
        name = os.path.basename(host)
        if stat.S_ISCHR(st.st_mode) and (os.major(st.st_rdev), os.minor(st.st_rdev)) == _WHITEOUT:
            _remove(name, dir_fd)
        elif stat.S_ISDIR(st.st_mode):
            if _overlay_attrs(host).get("user.overlay.opaque") == b"y":
                _remove(name, dir_fd)
            try:
                sub = os.open(name, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
            except OSError:  # missing, or a host file/link where the box now has a directory
                _remove(name, dir_fd)
                os.mkdir(name, stat.S_IMODE(st.st_mode) & 0o777, dir_fd=dir_fd)
                sub = os.open(name, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
            try:
                _apply(host, sub)
            finally:
                os.close(sub)
        elif stat.S_ISREG(st.st_mode):
            tmp = f".rbb-commit-{secrets.token_hex(8)}"  # O_EXCL: never clobbers a host file
            out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          stat.S_IMODE(st.st_mode) & 0o777, dir_fd=dir_fd)
            with open(host, "rb") as src, os.fdopen(out, "wb") as dst:
                shutil.copyfileobj(src, dst)
            old = _lstat(name, dir_fd)
            if old is not None and stat.S_ISDIR(old.st_mode):  # rename cannot replace a directory
                _remove(name, dir_fd)
            os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        # symlinks and special files: never committed


def discard(box: Box) -> None:
    """Drop every staged write. The server must be stopped."""
    for dest in box.folders:
        upper, work = box.layer(dest)
        for d in (upper, work):
            if os.path.isdir(d):
                for root, dirs, _ in os.walk(d):  # overlayfs leaves work/work at mode 000
                    for x in dirs:
                        os.chmod(os.path.join(root, x), 0o700)
                shutil.rmtree(d)


def info_pid(fd: int) -> int:
    """bwrap writes its info JSON in pieces and closes the fd: read to EOF."""
    buf = b""
    while chunk := os.read(fd, 4096):
        buf += chunk
    try:
        pid = json.loads(buf)["child-pid"]
    except (ValueError, KeyError, TypeError):
        raise BoxError("bwrap did not report a child pid") from None
    if not isinstance(pid, int) or pid <= 0:
        raise BoxError("bwrap reported a bad child pid")
    return pid
