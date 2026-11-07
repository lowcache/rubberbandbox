from rubberbandbox.demo import SECRET, run


def test_demo_story_holds():
    lines = []
    r = run(out=lines.append)
    assert not r["leaked"] and r["held"] == 3
    assert [s["to"] for s in r["sms"]] == ["+12065550101", "+12065550102"]  # forged + premium got nothing
    assert all("refund approved" not in s["body"] and "+1555" not in s["to"] for s in r["sms"])
    kinds = [e["kind"] for e in r["tools"]]
    assert kinds.count("git.push") == 1 and "http.post" not in kinds and "pkg.publish" not in kinds
    text = "\n".join(lines)
    assert "FOOLED" in text and "replays A1: refused" in text and SECRET not in text
