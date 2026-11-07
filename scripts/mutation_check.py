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
