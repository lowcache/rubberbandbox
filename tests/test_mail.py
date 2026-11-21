import hashlib
import ssl

import pytest

from rubberbandbox.mail import EmlSource, ImapSource, parse
from rubberbandbox.runtime import Malformed


def message(ar="mx.example.test; dmarc=pass; spf=pass; dkim=pass", body="SECRET BODY", extra=""):
    return ("From: Alice <ALICE@Example.Org>\nTo: owner@example.test\nSubject: Test\n"
            "Message-ID: <test-id@example.org>\n" + (f"Authentication-Results: {ar}\n" if ar else "") + extra + "\n" + body).encode()


def test_parse_trusts_only_topmost_matching_authentication_results_and_version_suffix():
    forged = message("mx.example.test; dmarc=fail", extra="Authentication-Results: mx.example.test; dmarc=pass\n")
    event = parse(forged, authserv_id="mx.example.test", include_body=False, received_at=1)
    assert not event.authenticated and event.meta["dmarc"] == "fail"
    other = message("other.example; dmarc=fail", extra="Authentication-Results: mx.example.test; dmarc=pass\n")
    assert not parse(other, authserv_id="mx.example.test", include_body=False, received_at=1).authenticated
    stamped_by_sender = message("attacker.example; dmarc=pass")  # a top header that is not the provider's
    assert not parse(stamped_by_sender, authserv_id="mx.example.test", include_body=False, received_at=1).authenticated
    assert parse(message("MX.EXAMPLE.TEST 1; dmarc=pass"), authserv_id="mx.example.test", include_body=False, received_at=1).authenticated
    missing = parse(message(None), authserv_id="mx.example.test", include_body=False, received_at=1)
    assert not missing.authenticated and missing.meta["dmarc"] == "none"


def test_parse_headers_only_body_and_sha_fallback():
    raw = message().replace(b"Message-ID: <test-id@example.org>\n", b"")
    headers = parse(raw, authserv_id="mx.example.test", include_body=False, received_at=1)
    body = parse(raw, authserv_id="mx.example.test", include_body=True, received_at=1)
    assert "SECRET BODY" not in headers.text and "SECRET BODY" in body.text
    assert headers.delivery_id == "sha256:" + hashlib.sha256(raw).hexdigest()


def test_eml_source_cursor_new_file_and_malformed(tmp_path):
    (tmp_path / "a.eml").write_bytes(message())
    source = EmlSource("mail", str(tmp_path), authserv_id="mx.example.test", clock=lambda: 1)
    items, cursor = source.poll(None)
    assert len(items) == 1 and cursor == "a.eml"
    (tmp_path / "b.eml").mkdir()
    (tmp_path / "c.eml").write_bytes(message())
    items, cursor = source.poll(cursor)
    assert isinstance(items[0], Malformed) and items[0].text == "b.eml"
    assert items[1].delivery_id == "test-id@example.org" and cursor == "c.eml"


class FakeImap:
    def __init__(self, uids=(8, 9, 10), validity="77", fail_fetch=None):
        self.uids, self.validity, self.fail_fetch, self.calls = uids, validity, fail_fetch, []
    def login(self, *a): self.calls.append(("login", a))
    def select(self, *a, **kw): self.calls.append(("select", a, kw)); return "OK", [b""]
    def response(self, name): self.calls.append(("response", name)); return "UIDVALIDITY", [self.validity.encode()]
    def status(self, *a): self.calls.append(("status", a)); return "OK", [b'INBOX (UIDNEXT 11)']
    def uid(self, command, *args):
        self.calls.append(("uid", command, args))
        if command == "SEARCH": return "OK", [" ".join(map(str, self.uids)).encode()]
        uid = int(args[0])
        if uid == self.fail_fetch: return "NO", []
        return "OK", [(b"x", message())]
    def logout(self): self.calls.append(("logout",))
    def store(self, *a): raise AssertionError("write")
    copy = move = expunge = append = store


def source(fake, **kwargs):
    seen = {}
    def connect(*args, **kw): seen.update(kw); return fake
    return ImapSource("imap", host="host", user="u", password="p", authserv_id="mx.example.test", connect=connect, **kwargs), seen


def test_imap_readonly_ssl_peek_backfill_batch_and_uid_filter():
    fake = FakeImap((7, 8, 9, 10))
    imap, seen = source(fake, backfill=3, batch=2)  # start after 7: 8, 9, 10, batched to 8, 9
    items, cursor = imap.poll(None)
    assert seen["ssl_context"].verify_mode == ssl.CERT_REQUIRED
    assert ("select", ("INBOX",), {"readonly": True}) in fake.calls
    fetches = [c for c in fake.calls if c[:2] == ("uid", "FETCH")]
    assert [c[2][0] for c in fetches] == ["8", "9"] and all("BODY.PEEK" in c[2][1] for c in fetches)
    assert cursor == "77:9" and len(items) == 2
    same = FakeImap((9,)); imap, _ = source(same)
    assert imap.poll("77:9") == ([], "77:9")


def test_imap_logout_uidvalidity_and_parse_failure(monkeypatch):
    bad = FakeImap((10,)); imap, _ = source(bad)
    monkeypatch.setattr("rubberbandbox.mail.parse", lambda *a, **kw: (_ for _ in ()).throw(ValueError("bad")))
    items, cursor = imap.poll("77:9")
    assert isinstance(items[0], Malformed) and items[0].line == 10 and cursor == "77:10"
    changed = FakeImap(validity="88"); imap, _ = source(changed)
    with pytest.raises(RuntimeError, match="uidvalidity changed"):
        imap.poll("77:9")
    assert ("logout",) in changed.calls
    failing = FakeImap((10,), fail_fetch=10); imap, _ = source(failing)
    with pytest.raises(RuntimeError): imap.poll("77:9")
    assert ("logout",) in failing.calls
