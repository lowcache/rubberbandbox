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
