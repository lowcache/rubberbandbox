from pathlib import Path

import pytest

from rubberbandbox.config import ConfigError, build, load
from rubberbandbox.core import ManualClock

ROOT = Path(__file__).resolve().parent.parent


def config_file(tmp_path, source, *, pack="triage"):
    path = tmp_path / "runtime.toml"
    path.write_text(f'''db = "{tmp_path / 'state.db'}"
mode = "shadow"
pack = "{pack}"
[clerk]
kind = "stub"
per_sender = 100
sender_window = 60
per_day = 1000
{source}
''')
    return path


def test_triage_eml_daemon_classifies_corpus_without_door_crossings(tmp_path, monkeypatch):
    clock = ManualClock()
    monkeypatch.setattr("rubberbandbox.config.time.time", clock)
    config = load(config_file(tmp_path, f'''[[source]]
kind = "eml"
name = "mail"
path = "{ROOT / 'corpus/mail_triage'}"
authserv_id = "mx.example.test"
include_body = true
'''))
    sb, runtime = build(config)
    try:
        runtime.run_once()
        assert sb.store.db.execute("SELECT COUNT(*) FROM classifications").fetchone() == (12,)
        events = [name for _, name, _ in sb.store.audit_log()]
        assert "door.sent" not in events and "shadow.withheld" not in events
        inbound = [detail for _, name, detail in sb.store.audit_log() if name == "inbound" and detail["delivery"] == "mail-07@example.org"]
        assert inbound == [{"channel": "mail", "delivery": "mail-07@example.org", "authenticated": False, "raw": inbound[0]["raw"]}]
    finally:
        runtime.close(); sb.store.db._conn.close()


def test_triage_config_rejects_unknown_kind_and_bad_imap_secret_refs(tmp_path):
    with pytest.raises(ConfigError): load(config_file(tmp_path, '[[source]]\nkind = "nope"\nname = "x"'))
    base = '[[source]]\nkind = "imap"\nname = "x"\nhost = "h"\nuser = "u"\nauthserv_id = "a"\n'
    with pytest.raises(ConfigError): load(config_file(tmp_path, base))
    with pytest.raises(ConfigError): load(config_file(tmp_path, base + 'password_env = "A"\npassword_file = "p"\n'))


def test_imap_secret_is_resolved_at_build_not_load(tmp_path):
    config = load(config_file(tmp_path, '[[source]]\nkind = "imap"\nname = "x"\nhost = "h"\nuser = "u"\nauthserv_id = "a"\npassword_env = "UNSET_MAIL_PASSWORD"\n'))
    with pytest.raises(ConfigError, match="cannot resolve secret"):
        build(config)


def test_triage_guide_states_the_url_bounds_the_airlock_enforces():
    from rubberbandbox.packs.triage.pack import CLERK_GUIDE, SCHEMA
    urls = SCHEMA.fields["urls"]
    assert f"longer than {urls.max_len} characters" in CLERK_GUIDE and f"up to {urls.max_items} URLs" in CLERK_GUIDE
    assert "never mailto:" in CLERK_GUIDE


def test_openrouter_clerk_is_built_with_its_model_and_the_triage_guide(tmp_path, monkeypatch):
    from rubberbandbox.clerks.openrouter import OpenRouterClerk
    from rubberbandbox.packs.triage.pack import CLERK_GUIDE
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    clerk = '[clerk]\nkind = "{}"\n{}per_sender = 2\nsender_window = 60\nper_day = 10\n'
    path = tmp_path / "runtime.toml"
    path.write_text(f'db = "{tmp_path / "state.db"}"\nmode = "shadow"\npack = "triage"\n' + clerk.format("openrouter", 'model = "x/y"\n'))
    sb, runtime = build(load(path))
    try:
        mounted = sb.mounts[0].clerk
        assert isinstance(mounted, OpenRouterClerk) and mounted.model == "x/y" and CLERK_GUIDE in mounted.system
    finally:
        runtime.close()
        sb.store.db._conn.close()
    path.write_text(f'db = "{tmp_path / "other.db"}"\nmode = "shadow"\npack = "triage"\n' + clerk.format("stub", 'model = "x/y"\n'))
    with pytest.raises(ConfigError, match="model applies only"):
        load(path)


def test_bulk_merges_spam_and_graymail_and_only_phishing_raises_a_notice(tmp_path, monkeypatch):
    import json
    from rubberbandbox.packs.triage.pack import SCHEMA
    monkeypatch.setattr("rubberbandbox.config.time.time", ManualClock())
    truth = json.loads((ROOT / "corpus/mail_triage/labels.json").read_text())
    assert set(truth.values()) == set(SCHEMA.fields["label"].choices) == {"legit", "bulk", "phishing"}
    config = load(config_file(tmp_path, f'[[source]]\nkind = "eml"\nname = "mail"\npath = "{ROOT / "corpus/mail_triage"}"\n'
                                         'authserv_id = "mx.example.test"\ninclude_body = true\n'))
    sb, runtime = build(config)
    try:
        runtime.run_once()
        labels = [json.loads(e)["label"] for (e,) in sb.store.db.execute("SELECT extracted FROM classifications WHERE status='ok'")]
        topics = {t for (t,) in sb.store.db.execute("SELECT topic FROM notices")}
        assert "bulk" in labels and "phishing" in labels and topics == {"phishing"}
    finally:
        runtime.close(); sb.store.db._conn.close()
