"""Mutation check: each mutant breaks one guard; the test suite must catch every one.

Run from the repo root: nix develop -c python scripts/mutation_check.py
Each mutant is applied to the working tree, the suite runs, and the file is restored."""
import subprocess
import sys
MUTANTS = {
  "door re-check disabled": ("rubberbandbox/core/invariant.py", '    spec = kinds.get(egress.kind)\n', '    return None\n    spec = kinds.get(egress.kind)\n'),
  "publish integrity ignored": ("rubberbandbox/core/invariant.py", 'if spec.publishes and not all(v.label.trusted for v in egress.payload):\n            return "publish with untrusted payload needs owner approval"', 'pass'),
  "lane accepts private payload": ("rubberbandbox/core/invariant.py", 'if not egress.payload or any(v.label != OWNER_PUBLIC for v in egress.payload):\n            return "public lane carries owner-published data only"', 'pass'),
  "public_read ignores labels": ("rubberbandbox/core/invariant.py", 'if not egress.destination.label.public or not all(v.label.public for v in egress.payload):\n            return "read carries or targets private-derived data"', 'pass'),
  "hands literals trusted+public": ("rubberbandbox/core/sandbox.py", 'return self.store.put(x["literal"], context, "hands", now)', 'return self.store.put(x["literal"], OWNER_PUBLIC, "hands", now)'),
  "no per-destination window": ("rubberbandbox/core/public_lane.py", 'if n >= cfg.per_destination:', 'if False:'),
  "geo allowlist off": ("rubberbandbox/packs/messaging/pack.py", 'if o.startswith(cfg.denied_prefixes) or not o.startswith(cfg.allowed_prefixes):', 'if False:'),
  "reply-to honored": ("rubberbandbox/packs/messaging/pack.py", 'return RouteReceipt(f"email:{env.lower()}"', 'return RouteReceipt(f"email:{(m.get(\'reply_to\') or env).lower()}"'),
  "door reuses batch time": ("rubberbandbox/core/door.py", "            now = self._clock()  # fresh per crossing", "            now = getattr(self, '_t', None) or self._clock(); self._t = now  #"),
  "lane slot lower bound off": ("rubberbandbox/core/invariant.py", "        if now < row[2]:\n            return \"before its slot\"", "        pass"),
  "unauthenticated may be public": ("rubberbandbox/core/sandbox.py", "        if not event.authenticated:  # unauthenticated", "        if False:  #"),
  "door trusts caller send_at": ("rubberbandbox/core/door.py", "            send_at = row[0] if row else None", "            pass"),
  "spend/delete grantable": ("rubberbandbox/core/manifest.py", "grantable=m.reviewed and m.effect not in _APPROVAL_ONLY and destinations <= 1,", "grantable=True,"),
  "door ignores grantable": ("rubberbandbox/core/invariant.py", '        if not spec.grantable:\n            return "kind needs owner approval per egress"', '        pass'),
  "grant ignores control taint": ("rubberbandbox/core/invariant.py", '        if not spec.read_only and not all(v.label.trusted for v in egress.control):\n            return "untrusted control args need owner approval"', '        pass'),
  "public_read ignores control": ("rubberbandbox/core/invariant.py", '        if not all(v.label.public for v in egress.control):\n            return "read is steered by private-derived data"', '        pass'),
  "door lane ignores control": ("rubberbandbox/core/invariant.py", '        if egress.control:\n            return "public lane carries no control args"', '        pass'),
  "typed refs unchecked": ("rubberbandbox/core/casefile.py", "if shape is not None and not shape.fullmatch(span):", "if False:"),
  "loosening does not invalidate": ("rubberbandbox/core/registry.py", "            if changed:  # each new loosened version kills what was authorized before it\n                self.sb.invalidate_kind(kind)", "            pass"),
  "loosened tool keeps its manifest": ("rubberbandbox/core/registry.py", '        if change.outcome == "loosened":\n            if changed:', '        if False:\n            if changed:'),
  "prose is hashed": ("rubberbandbox/core/registry.py", "        if k in _PROSE:\n            continue", "        if False:\n            continue"),
  "removed control arg is neutral": ("rubberbandbox/core/registry.py", '(loose if steers else other).append(f"{arg}: removed")', 'other.append(f"{arg}: removed")'),
  "annotation floor off": ("rubberbandbox/core/registry.py", "if _RANK[m.effect] < floor:", "if False:"),
  "enum widening ignored": ("rubberbandbox/core/registry.py", '    if "enum" in a:', '    if False:'),
  "hint flips ignored": ("rubberbandbox/core/registry.py", "(loose if b == unsafe else other).append(f\"{hint}: {a} -> {b}\")", "other.append(f\"{hint}: {a} -> {b}\")"),
  "new args allowed": ("rubberbandbox/core/registry.py", 'return f"args not approved: {unknown}" if unknown else None', 'return None'),
  "invalidation spares approvals": ("rubberbandbox/core/sandbox.py", "UPDATE approvals SET status='invalidated' WHERE id=?", "UPDATE approvals SET status=status WHERE id=?"),
  "invalidation spares grants": ("rubberbandbox/core/sandbox.py", "UPDATE grants SET ended=1 WHERE id=?", "UPDATE grants SET ended=ended WHERE id=?"),
  "invalidation spares receipts": ("rubberbandbox/core/sandbox.py", "UPDATE receipts SET consumed=1 WHERE kind=?", "UPDATE receipts SET consumed=consumed WHERE kind=?"),
  "endpoint not hashed": ("rubberbandbox/core/registry.py", '        "endpoint": endpoint,\n', '        "endpoint": "",\n'),
  "bones ignore unrolled args": ("rubberbandbox/core/registry.py", "    if live != declared:", "    if False:"),
  "bones ignore destination-like": ("rubberbandbox/core/registry.py", "if arg in m.args and m.args[arg] != \"destination\" and _destination_like(arg, schema):", "if False:"),
  "bones ignore control taint": ("rubberbandbox/core/sandbox.py", 'if not spec.read_only and not all(v.label.trusted for v in eg.control):\n        return "untrusted control args"', 'if False:\n        pass'),
  "door skips call check": ("rubberbandbox/core/door.py", "        if reason is None and self.calls is not None:\n            reason = self.calls(egress)", "        if False:\n            pass"),
  "unnamed calls without registry pass": ("rubberbandbox/core/door.py", '            reason = "named tool call with no registry to check it"', '            pass'),
  "role alignment unchecked": ("rubberbandbox/core/registry.py", '            return "call args are not in their approved roles"', '            pass'),
  "operator destination unchecked": ("rubberbandbox/core/registry.py", '            return "call with no destination arg must go to its operator"', '            pass'),
  "door accepts unnamed tool calls": ("rubberbandbox/core/registry.py", '            return "tool call without approved, named args"', '            return None'),
  "arg names not hashed": ("rubberbandbox/core/types.py", '            h.update(b"\\2names" + json.dumps(self.names).encode())', '            pass'),
  "output label ignores what was sent": ("rubberbandbox/core/door.py", "label = EXTERNAL_PUBLIC if spec.read_only and all(v.label.public for v in sent) else EXTERNAL_PRIVATE", "label = EXTERNAL_PUBLIC if spec.read_only else EXTERNAL_PRIVATE"),
  "mcp identity from serverInfo": ("rubberbandbox/mcp.py", "        if r.get(\"protocolVersion\") not in SUPPORTED:", "        object.__setattr__(self.cfg, 'name', r.get('serverInfo', {}).get('name', self.cfg.name))\n        if r.get(\"protocolVersion\") not in SUPPORTED:"),
  "endpoint ignores launch args": ("rubberbandbox/mcp.py", '"command": list(self.command)', '"command": list(self.command[:1])'),
  "absolute links resolve from the walk, not the box root": ("rubberbandbox/box.py", "                if target.startswith(\"/\"):\n                    while len(fds) > 1:", "                if False:\n                    while len(fds) > 1:"),
  "dotdot allowed below a missing component": ("rubberbandbox/box.py", '                if any(x in (".", "..") for x in rest):', '                if False:'),
  "paths under a file allowed": ("rubberbandbox/box.py", "            elif pending:\n                raise PathRejected", "            elif False:\n                raise PathRejected"),
  "grants match string prefixes": ("rubberbandbox/core/grants.py", "    return g is not None and d is not None and d[:len(g)] == g", "    return destination.startswith(granted)"),
  "non-normal path grants minted": ("rubberbandbox/core/grants.py", '        bad = [d for d in destinations if d.startswith("/") and _parts(d) is None]', '        bad = []'),
  "bind skips canonicalisation": ("rubberbandbox/core/registry.py", '                args = {a: self._canonical(kind, a, v) if roles[a] == "destination" else v for a, v in args.items()}', '                args = dict(args)'),
  "door skips path re-check": ("rubberbandbox/core/registry.py", "        return self._check_paths(eg, roles)", "        return None"),
  "moved path sent anyway": ("rubberbandbox/core/registry.py", "            if again != v.data:", "            if False:"),
  "stale box generation accepted": ("rubberbandbox/core/registry.py", "            if self._minted.get(v.id) != (server, box.generation):", "            if v.id not in self._minted:"),
  "moved path not re-held": ("rubberbandbox/core/sandbox.py", "        if status == \"refused\" and self.registry is not None and reason.startswith(PATH_MOVED):", "        if False:"),
  "boxed path filed as control": ("rubberbandbox/core/registry.py", '            if arg in m.args and m.args[arg] != "destination" and _PATH_NAMES.search(snake):', '            if False:'),
  "wider box counts as narrower": ("rubberbandbox/core/registry.py", "        if type(x) is not type(y) or not pairs(y) <= pairs(x):", "        if type(x) is not type(y):"),
  "box allowlist not in endpoint": ("rubberbandbox/mcp.py", '"cwd": self.cwd, "network": False, **self.box.identity()})', '"cwd": self.cwd, "network": False})'),
  "box keeps network": ("rubberbandbox/box.py", '"--unshare-all", "--unshare-user", "--disable-userns",', '"--unshare-user", "--disable-userns",'),
  "box drops clearenv": ("rubberbandbox/box.py", '"--new-session", "--clearenv"]', '"--new-session"]'),
  "box binds all of /nix": ("rubberbandbox/box.py", "    bound = closure([exe, *box.ro_paths])", "    bound = [\"/nix\"]"),
  "writes not staged": ("rubberbandbox/box.py", '        args += ["--overlay-src", host, "--overlay", upper, work, dest]', '        args += ["--bind", host, dest]'),
  "commit writes through host links": ("rubberbandbox/box.py", '            tmp = f".rbb-commit-{secrets.token_hex(8)}"  # O_EXCL: never clobbers a host file\n            out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,', '            tmp = name\n            out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC,'),
  "unknown overlay metadata accepted": ("rubberbandbox/box.py", "            elif set(attrs) - _BENIGN:", "            elif False:"),
  "box symlinks committed": ("rubberbandbox/box.py", "        # symlinks and special files: never committed", "        elif stat.S_ISLNK(st.st_mode):\n            os.symlink(os.readlink(host), name, dir_fd=dir_fd)"),
  "socket source type unchecked": ("rubberbandbox/box.py", "            if not stat.S_ISSOCK(os.stat(h).st_mode):", "            if False:"),
  "box mounts may overlap": ("rubberbandbox/box.py", "                if ca == cb or cb[:len(ca)] == ca or ca[:len(cb)] == cb:", "                if ca == cb:"),
  "wholesale read-only paths": ("rubberbandbox/box.py", '            if parts is None or len(parts) < 2 or (not in_store and "/" + parts[0] in _RESERVED):', '            if parts is None:'),
  "host paths not pinned": ("rubberbandbox/box.py", "            if os.path.realpath(h) != h:", "            if False:"),
  "commit follows intermediate links": ("rubberbandbox/box.py", "            fd = _open_nofollow(host)", "            fd = os.open(host, os.O_DIRECTORY | os.O_CLOEXEC)"),
  "commit temp name predictable": ("rubberbandbox/box.py", '            tmp = f".rbb-commit-{secrets.token_hex(8)}"', '            tmp = f".rbb-commit-{name}"'),
  "list-ness taken from the value": ("rubberbandbox/core/registry.py", "        if not many:\n            return box.resolve(data)", "        if not data.startswith(\"[\"):\n            return box.resolve(data)"),
  "path-list destinations grantable": ("rubberbandbox/core/registry.py", "            spec = replace(spec, grantable=False)", "            pass"),
  "unreviewed boxed tools callable": ("rubberbandbox/core/registry.py", "        if kind.partition(\"/\")[0] in self.boxes and self._reverted(kind):", "        if False:"),
  "door skips unreviewed-in-box check": ("rubberbandbox/core/registry.py", "        blocked = self._unreviewed_in_box(eg.kind)\n        if blocked:\n            return blocked\n        roles = self.roles(eg.kind)", "        roles = self.roles(eg.kind)"),
  "unconfigured boxes accepted": ("rubberbandbox/core/registry.py", "        if set(self.boxes) - set(self.endpoints):  # an unconfigured box", "        if False:  # an unconfigured box"),
}
caught = 0
for name, (path, old, new) in MUTANTS.items():
    src = open(path).read()
    assert src.count(old) == 1, (name, "anchor not found")
    open(path, "w").write(src.replace(old, new))
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider"], capture_output=True, text=True)
    finally:
        open(path, "w").write(src)
    ok = r.returncode != 0
    caught += ok
    print(("CAUGHT " if ok else "MISSED ") + name)
print(f"{caught}/{len(MUTANTS)} mutants caught")
