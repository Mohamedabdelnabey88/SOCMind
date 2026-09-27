from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Iterable

from .models import Event

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)
HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b")
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


@dataclass(frozen=True, slots=True)
class IOC:
    type: str
    value: str
    scope: str


def _scope_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    if ip.is_private:
        return "private"
    if ip.is_loopback:
        return "loopback"
    if ip.is_reserved:
        return "reserved"
    return "public"


def _event_text(event: Event) -> str:
    parts = [
        event.user or "",
        event.process or "",
        event.parent_process or "",
        event.src_ip or "",
        event.dst_ip or "",
        event.command_line or "",
        json.dumps(event.data, ensure_ascii=False, default=str),
    ]
    return " ".join(parts)


def extract_iocs(events: Iterable[Event]) -> list[IOC]:
    found: set[IOC] = set()
    for event in events:
        text = _event_text(event)
        for value in IP_RE.findall(text):
            scope = _scope_ip(value)
            if scope != "invalid":
                found.add(IOC("ip", value, scope))
        for value in URL_RE.findall(text):
            found.add(IOC("url", value.rstrip(".,);]"), "network"))
        for value in HASH_RE.findall(text):
            kind = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
            found.add(IOC(kind, value.lower(), "file"))
        for value in DOMAIN_RE.findall(text):
            # Skip dotted IPv4 captured by permissive domain-like patterns.
            try:
                ipaddress.ip_address(value)
                continue
            except ValueError:
                pass
            found.add(IOC("domain", value.lower().rstrip("."), "network"))
    return sorted(found, key=lambda item: (item.type, item.value))
