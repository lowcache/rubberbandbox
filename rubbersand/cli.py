"""python -m rubbersand.cli attacks [path] | clean [path] [--clerk claude]"""

from __future__ import annotations

import sys

from rubbersand.packs.messaging.corpus import run_attacks, run_clean


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "attacks"
    if cmd == "attacks":
        results = run_attacks(argv[1] if len(argv) > 1 else "corpus/messaging_attacks.json")
        for r in results:
            mark = "ok  " if r.ok else "FAIL"
            print(f"{mark} {r.name:42} expected={r.expected} got={r.got}" + (f" LEAKS={r.leaks}" if r.leaks else ""))
        failed = sum(not r.ok for r in results)
        print(f"\n{len(results) - failed}/{len(results)} attack cases behave as specified")
        return 1 if failed else 0
    if cmd == "clean":
        args = [a for a in argv[1:] if not a.startswith("--")]
        clerk = None
        if "--clerk" in argv and argv[argv.index("--clerk") + 1] == "claude":
            from rubbersand.clerks.claude import ClaudeClerk
            from rubbersand.packs.messaging import CLERK_GUIDE, SCHEMA

            clerk = ClaudeClerk(SCHEMA, CLERK_GUIDE)
            args = [a for a in args if a != "claude"]
        rep = run_clean(args[0] if args else "corpus/messaging_clean.json", clerk)
        print(f"messages {rep.messages}  replies {rep.replies}  holds {rep.holds}  "
              f"owner notices (batched into the digest) {rep.notices}")
        print(f"clerk accuracy {rep.clerk_correct}/{rep.messages}")
        for name, exp, got in rep.misclassified:
            print(f"  misclassified {name}: expected {exp}, got {got}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
