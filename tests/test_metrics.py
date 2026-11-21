import json
import random

import pytest

from rubberbandbox.config import build, load
from rubberbandbox.core import ClerkBudget, EXTERNAL_PRIVATE
from rubberbandbox.packs.messaging import KeywordClerk
from test_console import env, run
from test_runtime import config_file, event


class RaisingClerk:
    def extract(self, text):
        raise RuntimeError("offline")


class RejectingClerk:
    def __init__(self, output):
        self.output = output

    def extract(self, text):
        return self.output


@pytest.mark.parametrize("status,clerk,output", [
    ("ok", KeywordClerk(), KeywordClerk().extract("price?")),
    ("error", RaisingClerk(), None),
    ("budget", KeywordClerk(), None),
    ("rejected", RejectingClerk({"bad": "value"}), {"bad": "value"}),
    ("rejected", RejectingClerk({"bad": object()}), None),
    ("rejected", RejectingClerk(None), None),
])
def test_classifications_preserve_routing(env, tmp_path, monkeypatch, status, clerk, output):
    sb, _, clock, _, _ = env
    other = tmp_path / "without"
    other.mkdir()
    baseline, runtime = build(load(config_file(other)))
    try:
        execute = baseline.store.db.execute
        execute("DROP TABLE classifications")

        def without_classifications(sql, params=()):
            if sql.startswith("INSERT INTO classifications"):
                return None
            return execute(sql, params)

        monkeypatch.setattr(baseline.store.db, "execute", without_classifications)
        for box in (sb, baseline):
            object.__setattr__(box.mounts[0], "clerk", clerk)
            box.lane.rng = random.Random(0)
            if status == "budget":
                box.clerk_budget = ClerkBudget(0, 60, 100)
        incoming = event(clock, text="price?")
        assert sb.receive(incoming) == baseline.receive(incoming)
        rows = sb.store.db.execute("SELECT raw, channel, at, extracted, status FROM classifications").fetchall()
        raw = sb.store.db.execute("SELECT detail FROM audit WHERE event='inbound'").fetchone()[0]
        expected = json.dumps(output, sort_keys=True) if output is not None else None
        if status == "rejected" and clerk.output is None:
            expected = "null"
        assert rows == [(json.loads(raw)["raw"], "sms", clock(), expected, status)]
    finally:
        runtime.close()
        baseline.store.db._conn.close()


def add(env, label=None, predicted="a", status="ok", age=0, text="hello"):
    sb, _, clock, _, _ = env
    raw = sb.store.put(text, EXTERNAL_PRIVATE, "sms", clock()).id
    extracted = json.dumps({"need": predicted}) if predicted is not None else "{}"
    sb.store.db.execute("INSERT INTO classifications VALUES (?,?,?,?,?)",
                        (raw, "sms", clock() - age, extracted, status))
    if label is not None:
        sb.store.db.execute("INSERT INTO labels VALUES (?,?,?)", (raw, label, clock()))
    return raw


@pytest.mark.parametrize("raw,label", [("bad", "a"), ("V01", "a"), ("V999999", "a"),
                                       (None, "Bad"), (None, "a b"), (None, "a" * 33), (None, "a\x1b")])
def test_invalid_labels_write_nothing(env, raw, label):
    valid = add(env, "existing")
    before = env[0].store.db.execute("SELECT * FROM labels").fetchall()
    with pytest.raises(SystemExit) as exc:
        run(env, "label", raw or valid, label)
    assert exc.value.code == 2
    assert env[0].store.db.execute("SELECT * FROM labels").fetchall() == before


def test_label_replaces_owner_data_directly(env, capsys):
    raw = add(env)
    for label in ("a", "other_1-name"):
        assert run(env, "label", raw, label) == 0
        assert capsys.readouterr().out == f"{raw}\t{label}\n"
        assert env[0].store.db.execute("SELECT * FROM labels").fetchall() == [(raw, label, env[2]())]
    assert env[0].store.db.execute("SELECT * FROM owner_queue").fetchall() == []


def test_metrics_exact_confusions(env, capsys):
    for label, predicted in [("a", "a"), ("a", "a"), ("a", "b"),
                             ("b", "b"), ("c", "a"), ("c", "b")]:
        add(env, label, predicted)
    run(env, "metrics", "--field", "need")
    assert capsys.readouterr().out == (
        "class\tprecision\trecall\tsupport\n"
        "a\t0.666667\t0.666667\t3\n"
        "b\t0.333333\t1.000000\t1\n"
        "c\t-\t0.000000\t2\n"
        "accuracy\t0.500000\t3/6\n"
        "a -> a: 2\na -> b: 1\nb -> b: 1\nc -> a: 1\nc -> b: 1\n"
        "excluded\tbudget\t0\nexcluded\terror\t0\nexcluded\trejected\t0\n"
    )


def test_non_ok_rows_are_excluded(env, capsys):
    add(env, "a", "a")
    for status in ("budget", "error", "rejected"):
        add(env, "a", "a", status)
    run(env, "metrics", "--field", "need")
    assert capsys.readouterr().out == (
        "class\tprecision\trecall\tsupport\na\t1.000000\t1.000000\t1\n"
        "accuracy\t1.000000\t1/1\na -> a: 1\n"
        "excluded\tbudget\t1\nexcluded\terror\t1\nexcluded\trejected\t1\n"
    )


def test_missing_field_and_no_predictions(env, capsys):
    add(env, "a", None)
    run(env, "metrics", "--field", "need")
    assert "a -> (none): 1\n" in capsys.readouterr().out
    env[0].store.db.execute("UPDATE classifications SET status='error'")
    run(env, "metrics", "--field", "need")
    assert capsys.readouterr().out == (
        "class\tprecision\trecall\tsupport\naccuracy\t-\t0/0\n"
        "excluded\tbudget\t0\nexcluded\terror\t1\nexcluded\trejected\t0\n"
    )


def test_metrics_empty(env, capsys):
    add(env)
    run(env, "metrics", "--field", "need")
    assert capsys.readouterr().out == "no labeled classifications\n"


def test_sample_filters_limits_and_sanitises(env, capsys):
    add(env, "labeled")
    add(env, age=86401)
    add(env, age=-1)
    text = "\x1b" + "x" * 600
    expected = {add(env, status=status, text=text): status for status in ("ok", "budget", "error", "rejected")}
    run(env, "sample", "--n", "10")
    lines = capsys.readouterr().out.splitlines()
    assert {line.split("\t")[0] for line in lines} == expected.keys()
    for line in lines:
        raw, status, extracted, message = line.split("\t")
        assert status == expected[raw]
        assert json.loads(extracted) == {"need": "a"}
        assert message == "\\x1b" + "x" * 499
    run(env, "sample", "--n", "2", "--hours", "1")
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2
    assert len({line.split("\t")[0] for line in lines}) == 2
    assert all(line.split("\t")[0] in expected for line in lines)
