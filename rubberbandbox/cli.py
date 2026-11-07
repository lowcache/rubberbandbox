"""python -m rubberbandbox.cli attacks [path] | clean [path] [--clerk claude|codex] | adversarial [path] [--clerk claude|codex] | demo [--clerk claude|codex] [--pace SECONDS]"""

from __future__ import annotations

import sys

from rubberbandbox.packs.messaging.corpus import run_adversarial, run_attacks, run_clean


def _colorize(line: str) -> str:
    """Highlight the story beats when writing to a terminal (the demo GIF is recorded from one)."""
    import re

    bold, dim, red, green, yellow, cyan, reset = (f"\033[{c}m" for c in ("1", "2", "1;31", "32", "33", "1;36", "0"))
    if line.lstrip("\n").startswith("=="):
        return f"{cyan}{line}{reset}"
    if line.lstrip().startswith("audit"):
        return f"{dim}{line}{reset}"
    if line.lstrip().startswith("OUT"):
        return f"{green}{line}{reset}"
    line = re.sub(r"\(FOOLED[^)]*\)", lambda m: f"{red}{m.group(0)}{reset}", line)
    line = re.sub(r"\b(held|refused)\b", lambda m: f"{yellow}{bold}{m.group(0)}{reset}", line)
    line = line.replace("credential leaked: no", f"{green}{bold}credential leaked: no{reset}")
    return line.replace("(correct)", f"{green}(correct){reset}")


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
    if cmd == "demo":
        from rubberbandbox.demo import run

        clerk = None
        if "--clerk" in argv:
            from rubberbandbox.packs.messaging import CLERK_GUIDE, SCHEMA

            name = argv[argv.index("--clerk") + 1]
            if name == "codex":
                from rubberbandbox.clerks.codex import CodexClerk as Clerk
            else:
                from rubberbandbox.clerks.claude import ClaudeClerk as Clerk
            clerk = Clerk(SCHEMA, CLERK_GUIDE)
        pace = float(argv[argv.index("--pace") + 1]) if "--pace" in argv else 0.0
        out = (lambda line: print(_colorize(line))) if sys.stdout.isatty() else print
        return 1 if run(clerk, out=out, pace=pace)["leaked"] else 0
    if cmd in ("clean", "adversarial"):
        args = [a for a in argv[1:] if not a.startswith("--")]
        clerk = None
        if "--clerk" in argv:
            from rubberbandbox.packs.messaging import CLERK_GUIDE, SCHEMA

            name = argv[argv.index("--clerk") + 1]
            if name == "claude":
                from rubberbandbox.clerks.claude import ClaudeClerk as Clerk
            elif name == "codex":
                from rubberbandbox.clerks.codex import CodexClerk as Clerk
            else:
                print(f"unknown clerk {name!r}: claude | codex")
                return 2
            clerk = Clerk(SCHEMA, CLERK_GUIDE)
            args = [a for a in args if a != name]
        if cmd == "adversarial":
            adv = run_adversarial(args[0] if args else "corpus/messaging_adversarial.json", clerk)
            judged = adv.messages - len(adv.abstained)
            print(f"messages {adv.messages}  replies {adv.replies}")
            print(f"FOOLED    {len(adv.fooled)}/{judged} classified messages got the wrong label")
            print(f"ABSTAINED {len(adv.abstained)}/{adv.messages} (clerk failed closed: owner notice, no action)")
            print(f"HARM      {len(adv.harm)}  <- the claim is that this is always 0")
            for name, cat, exp, got in adv.fooled:
                print(f"  fooled  [{cat}] {name}: expected {exp}, got {got}")
            for name, cat in adv.abstained:
                print(f"  abstain [{cat}] {name}")
            for name, what in adv.harm:
                print(f"  HARM    {name}: {what}")
            return 1 if adv.harm else 0
        rep = run_clean(args[0] if args else "corpus/messaging_clean.json", clerk)
        if rep.clerk_errors:
            print(f"CLERK ERRORS on {sum(rep.clerk_errors.values())}/{rep.messages} messages (each failed closed):")
            for err, n in rep.clerk_errors.items():
                print(f"  {n}x {err[:300]}")
            if sum(rep.clerk_errors.values()) == rep.messages:
                print("every call failed: accuracy below is not a measurement")
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
