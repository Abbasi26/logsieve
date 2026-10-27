"""Minimal EVTX writer for fictional records.

python-evtx reads the Windows event-log binary format. The real writer is
Windows itself. This module emits one chunk with a resident binary-XML
template so tests and ``logsieve demo`` can exercise that reader without a
Windows machine and without shipping somebody else's log.

It is not a general EVTX writer. Records are element trees of Unicode text.
"""

from __future__ import annotations

import binascii
import struct
from datetime import datetime, timezone
from typing import Iterable


def _name_bytes(text: str) -> bytes:
    # NameStringNode stores a character count, UTF-16LE bytes, then two extra
    # bytes that the parser skips when it computes the node length.
    return struct.pack("<IHH", 0, 0, len(text)) + text.encode("utf-16-le") + b"\x00\x00"


def _value(text: str) -> bytes:
    return bytes([0x05, 0x01]) + struct.pack("<H", len(text)) + text.encode("utf-16-le")


def _template_data(base: int, nodes: list) -> bytes:
    cursor = 0

    def add_element(name: str, inner_builder) -> bytes:
        nonlocal cursor
        name_blob = _name_bytes(name)
        saved = cursor
        cursor = saved + 11 + len(name_blob) + 1
        inner = inner_builder()
        cursor = saved
        header = struct.pack("<BHII", 0x01, 0, 0, base + cursor + 11)
        blob = header + name_blob + bytes([0x02]) + inner + bytes([0x04])
        cursor = saved + len(blob)
        return blob

    def emit(node) -> bytes:
        kind = node[0]
        if kind == "text":
            _, name, text = node
            return add_element(name, lambda: _value(text))
        _, name, children = node
        return add_element(name, lambda: b"".join(emit(child) for child in children))

    data = b"".join(emit(node) for node in nodes)
    return data + bytes([0x00])


def _filetime(when: datetime) -> int:
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((when.astimezone(timezone.utc) - epoch).total_seconds() * 10_000_000)


def _record(template_data: bytes, record_offset: int, record_num: int, when: datetime) -> bytes:
    # Record layout: 0x18 byte header, 10 byte template instance, 0x18 byte
    # template header, then the template bytes. 0x18 + 10 + 0x18 = 0x3A.
    template_offset = record_offset + 0x22
    template = struct.pack("<I", 0) + (b"\x00" * 16) + struct.pack("<I", len(template_data))
    instance = bytes([0x0C, 0x00]) + struct.pack("<II", 0, template_offset)
    bxml = instance + template + template_data + struct.pack("<I", 0)
    size = 0x18 + len(bxml) + 4
    header = struct.pack("<IIQ", 0x00002A2A, size, record_num) + struct.pack("<Q", _filetime(when))
    return header + bxml + struct.pack("<I", size)


def _event_tree(event: dict) -> list:
    system_children = [
        ("text", "Provider", event.get("provider") or "Application"),
        ("text", "EventID", str(event.get("event_id") or "")),
        ("text", "Level", str(event.get("level") or "4")),
        ("text", "Computer", event.get("computer") or ""),
        ("text", "TimeCreated", event.get("time") or ""),
    ]
    if event.get("user"):
        system_children.append(("text", "UserID", event["user"]))
    children = [("group", "System", system_children)]
    data = event.get("data") or {}
    if data:
        children.append(("group", "EventData", [("text", key, value) for key, value in data.items()]))
    message = event.get("message") or ""
    if message:
        children.append(("group", "RenderingInfo", [("text", "Message", message)]))
    return [("group", "Event", children)]


def build_evtx(events: Iterable[dict]) -> bytes:
    """Return a complete one-chunk EVTX file for ``events``.

    Each event dict may contain ``provider``, ``event_id``, ``level``,
    ``computer``, ``time`` (ISO-8601 text), ``user``, ``message``, and
    ``data`` (a dict of extra name/value strings). ``when`` may be a
    datetime; otherwise ``time`` is parsed, and missing times become UTC now
    only for the record header. Prefer passing ``when`` from tests.
    """
    prepared = []
    offset = 0x200
    for index, event in enumerate(events, start=1):
        when = event.get("when")
        if not isinstance(when, datetime):
            raw = event.get("time") or ""
            candidate = raw.replace("Z", "+00:00")
            try:
                when = datetime.fromisoformat(candidate)
            except ValueError:
                when = datetime(1970, 1, 1, tzinfo=timezone.utc)
        tree = _event_tree(event)
        data = _template_data(offset + 0x3A, tree)
        record = _record(data, offset, index, when)
        prepared.append(record)
        offset += len(record)
        if offset > 0x10000 - 16:
            raise ValueError("synthetic EVTX chunk is full")
    if not prepared:
        raise ValueError("synthetic EVTX needs at least one event")

    chunk = bytearray(0x10000)
    chunk[0:8] = b"ElfChnk\x00"
    count = len(prepared)
    struct.pack_into("<QQQQ", chunk, 8, 1, count, 1, count)
    next_offset = 0x200 + sum(len(record) for record in prepared)
    last_offset = 0x200
    cursor = 0x200
    for record in prepared:
        chunk[cursor : cursor + len(record)] = record
        last_offset = cursor
        cursor += len(record)
    struct.pack_into("<III", chunk, 0x28, 0x80, last_offset, next_offset)
    data_crc = binascii.crc32(chunk[0x200:next_offset]) & 0xFFFFFFFF
    struct.pack_into("<I", chunk, 0x34, data_crc)
    header_crc = binascii.crc32(bytes(chunk[0:0x78]) + bytes(chunk[0x80:0x200])) & 0xFFFFFFFF
    struct.pack_into("<I", chunk, 0x7C, header_crc)

    header = bytearray(0x1000)
    header[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQ", header, 8, 0, 0, count + 1)
    struct.pack_into("<I", header, 0x20, 0x80)
    struct.pack_into("<HHHH", header, 0x24, 1, 3, 0x1000, 1)
    file_crc = binascii.crc32(bytes(header[:0x78])) & 0xFFFFFFFF
    struct.pack_into("<I", header, 0x7C, file_crc)
    return bytes(header) + bytes(chunk)