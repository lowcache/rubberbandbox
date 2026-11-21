"""Mail ingestion sources; these only read mailbox state."""
from __future__ import annotations

import email
import email.policy
import hashlib
import imaplib
import re
import ssl
import time
from email.header import decode_header, make_header
from email.utils import getaddresses
from html import unescape
from pathlib import Path

from .core import InboundEvent
from .runtime import Malformed


def _decode(value: str | None) -> str:
    return str(make_header(decode_header(value or "")))


def _body(message: email.message.Message) -> str:
    parts = list(message.walk()) if message.is_multipart() else [message]
    plain = next((p for p in parts if p.get_content_type() == "text/plain" and not p.get_filename()), None)
    part = plain or next((p for p in parts if p.get_content_type() == "text/html" and not p.get_filename()), None)
    if part is None:
        return ""
    text = part.get_content()
    if not isinstance(text, str):
        text = text.decode(part.get_content_charset() or "utf-8", "replace")
    if part.get_content_type() == "text/html":
        text = unescape(re.sub(r"<[^>]*>", "", text))
    return text[:8000]


def parse(raw: bytes, *, authserv_id: str, include_body: bool, received_at: float) -> InboundEvent:
    message = email.message_from_bytes(raw, policy=email.policy.default)
    senders = [address.lower() for _, address in getaddresses(message.get_all("From", [])) if address]
    origin = senders[0] if len(senders) == 1 else ""
    delivery = (message.get("Message-ID") or "").strip().strip("<>")
    if not delivery:
        delivery = "sha256:" + hashlib.sha256(raw).hexdigest()
    results = {"dmarc": "none", "spf": "none", "dkim": "none"}
    # RFC 8601: only the topmost header can be the receiving provider's own; any lower one, or a top one
    # from another authserv-id, may be the sender's forgery. authserv-id may carry a version: "id 1".
    top = (message.get_all("Authentication-Results") or [""])[0]
    authority, sep, rest = str(top).partition(";")
    if sep and [a.lower() for a in authority.split()[:1]] == [authserv_id.lower()]:
        for method in results:
            found = re.search(r"(?:^|[;\s])" + method + r"\s*=\s*([^\s;]+)", rest, re.I)
            if found:
                results[method] = found.group(1).lower()
    lines = []
    for name in ("From", "Reply-To", "To", "Subject", "List-Id", "List-Unsubscribe"):
        value = message.get(name)
        if value is not None:
            lines.append(f"{name}: {_decode(value)}")
    attachments = sum(1 for p in (message.walk() if message.is_multipart() else [message]) if p.get_filename())
    lines.append(f"Attachments: {attachments}")
    if include_body:
        lines.extend(("", _body(message)))
    unsub = re.findall(r"<([^>]+)>", message.get("List-Unsubscribe", ""))
    meta = {"from": senders, **results, "list_id": _decode(message.get("List-Id")) or None,
            "list_unsubscribe": unsub, "auto_submitted": _decode(message.get("Auto-Submitted")) or "no",
            "attachments": attachments}
    return InboundEvent("mail", results["dmarc"] == "pass", origin, delivery, "\n".join(lines), received_at, meta)


class EmlSource:
    def __init__(self, name: str, directory: str, *, authserv_id: str, include_body: bool = False, clock=time.time) -> None:
        self.name, self.directory, self.authserv_id, self.include_body, self.clock = name, directory, authserv_id, include_body, clock

    def poll(self, cursor: str | None):
        items = []
        names = sorted(p.name for p in Path(self.directory).glob("*.eml"))
        pending = [name for name in names if cursor is None or name > cursor]
        for name in pending:
            try:
                items.append(parse((Path(self.directory) / name).read_bytes(), authserv_id=self.authserv_id,
                                   include_body=self.include_body, received_at=self.clock()))
            except Exception as exc:
                items.append(Malformed(0, name, repr(exc)))
        return items, (pending[-1] if pending else cursor)


class ImapSource:
    def __init__(self, name: str, *, host: str, port: int = 993, user: str, password: str, mailbox: str = "INBOX",
                 authserv_id: str, include_body: bool = False, backfill: int = 0, batch: int = 50,
                 timeout: float = 30.0, connect=imaplib.IMAP4_SSL) -> None:
        self.name, self.host, self.port, self.user, self.password, self.mailbox = name, host, port, user, password, mailbox
        self.authserv_id, self.include_body, self.backfill, self.batch, self.timeout, self.connect = authserv_id, include_body, backfill, batch, timeout, connect

    def poll(self, cursor: str | None):
        # imaplib's default context does not verify certificates; the password must not go to an impostor
        client = self.connect(self.host, self.port, timeout=self.timeout, ssl_context=ssl.create_default_context())
        try:
            client.login(self.user, self.password)
            status, data = client.select(self.mailbox, readonly=True)
            if status != "OK": raise RuntimeError("cannot select mailbox")
            values = client.response("UIDVALIDITY")[1] if hasattr(client, "response") else []
            validity = str(values[0].decode() if values and isinstance(values[0], bytes) else values[0]) if values else ""
            status, uidnext_data = client.status(self.mailbox, "(UIDNEXT)")
            if status != "OK": raise RuntimeError("cannot read UIDNEXT")
            match = re.search(r"UIDNEXT\s+(\d+)", str(uidnext_data[0]))
            uidnext = int(match.group(1)) if match else 0
            if cursor:
                old_validity, last = cursor.split(":", 1)
                if old_validity != validity: raise RuntimeError("uidvalidity changed: owner must reset the cursor")
                start = int(last)
            else:
                start = max(0, uidnext - 1 - self.backfill)
            status, found = client.uid("SEARCH", None, f"UID {start + 1}:*")
            if status != "OK": raise RuntimeError("UID search failed")
            # "N:*" also matches the highest UID when nothing is above N: keep only UIDs past the cursor
            uids = sorted(u for u in (int(x) for x in (found[0].split() if found and found[0] else [])) if u > start)
            uids = uids[:self.batch]
            items = []
            last = start
            for uid in uids:
                status, fetched = client.uid("FETCH", str(uid), "(BODY.PEEK[])" if self.include_body else "(BODY.PEEK[HEADER])")
                if status != "OK": raise RuntimeError("UID fetch failed")
                raw = next((x[1] for x in fetched if isinstance(x, tuple) and isinstance(x[1], bytes)), b"")
                try:
                    items.append(parse(raw, authserv_id=self.authserv_id, include_body=self.include_body,
                                       received_at=time.time()))
                except Exception as exc:  # quarantined by the runtime; never retried, never stalls the source
                    items.append(Malformed(uid, f"{self.mailbox} uid {uid}", repr(exc)))
                last = uid
            return items, f"{validity}:{last}"
        finally:
            try: client.logout()
            except Exception: pass
