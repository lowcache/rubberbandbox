"""Mutation check: each mutant breaks one guard; the test suite must catch every one.

Run from the repo root: nix develop -c python scripts/mutation_check.py
Each mutant is applied to the working tree, the suite runs, and the file is restored."""
import subprocess
import sys
MUTANTS = {
  "door re-check disabled": ("rubbersand/core/invariant.py", '    spec = kinds.get(egress.kind)\n', '    return None\n    spec = kinds.get(egress.kind)\n'),
  "publish integrity ignored": ("rubbersand/core/invariant.py", 'if spec.publishes and not all(v.label.trusted for v in egress.payload):\n            return "publish with untrusted payload needs owner approval"', 'pass'),
  "lane accepts private payload": ("rubbersand/core/invariant.py", 'if not egress.payload or any(v.label != OWNER_PUBLIC for v in egress.payload):\n            return "public lane carries owner-published data only"', 'pass'),
  "public_read ignores labels": ("rubbersand/core/invariant.py", 'if not egress.destination.label.public or not all(v.label.public for v in egress.payload):\n            return "read carries or targets private-derived data"', 'pass'),
  "hands literals trusted+public": ("rubbersand/core/sandbox.py", 'return self.store.put(x["literal"], context, "hands", now)', 'return self.store.put(x["literal"], OWNER_PUBLIC, "hands", now)'),
  "no per-destination window": ("rubbersand/core/public_lane.py", 'if n >= cfg.per_destination:', 'if False:'),
  "geo allowlist off": ("rubbersand/packs/messaging/pack.py", 'if o.startswith(cfg.denied_prefixes) or not o.startswith(cfg.allowed_prefixes):', 'if False:'),
  "reply-to honored": ("rubbersand/packs/messaging/pack.py", 'return RouteReceipt(f"email:{env.lower()}"', 'return RouteReceipt(f"email:{(m.get(\'reply_to\') or env).lower()}"'),
  "door reuses batch time": ("rubbersand/core/door.py", "            now = self._clock()  # fresh per crossing", "            now = getattr(self, '_t', None) or self._clock(); self._t = now  #"),
  "lane slot lower bound off": ("rubbersand/core/invariant.py", "        if now < row[2]:\n            return \"before its slot\"", "        pass"),
  "unauthenticated may be public": ("rubbersand/core/sandbox.py", "        if not event.authenticated:  # unauthenticated", "        if False:  #"),
  "door trusts caller send_at": ("rubbersand/core/door.py", "            send_at = row[0] if row else None", "            pass"),
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
