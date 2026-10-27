from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from logsieve.pseudo.vault import Mapping

STOPWORDS = {
    "admin",
    "agent",
    "application",
    "cache",
    "client",
    "code",
    "config",
    "content",
    "data",
    "date",
    "debug",
    "default",
    "domain",
    "download",
    "error",
    "executor",
    "failed",
    "failure",
    "false",
    "file",
    "files",
    "health",
    "host",
    "http",
    "https",
    "info",
    "install",
    "intune",
    "local",
    "manager",
    "microsoft",
    "name",
    "network",
    "none",
    "null",
    "package",
    "policy",
    "program",
    "script",
    "server",
    "service",
    "success",
    "system",
    "temp",
    "thread",
    "time",
    "true",
    "type",
    "update",
    "user",
    "users",
    "warning",
    "windows",
}
FILE_TLDS = {
    "bin",
    "cab",
    "cat",
    "config",
    "csv",
    "dat",
    "dll",
    "etl",
    "evtx",
    "exe",
    "gif",
    "gz",
    "htm",
    "html",
    "inf",
    "ini",
    "jpg",
    "jpeg",
    "json",
    "key",
    "cer",
    "crt",
    "pem",
    "jsonl",
    "log",
    "ndjson",
    "md",
    "msi",
    "msp",
    "msu",
    "mui",
    "ocx",
    "pdb",
    "png",
    "ps1",
    "sys",
    "tmp",
    "txt",
    "xml",
    "yaml",
    "yml",
    "zip",
}
COMMON_LABELS = FILE_TLDS | STOPWORDS | {
    "ad",
    "com",
    "corp",
    "example",
    "home",
    "internal",
    "invalid",
    "lan",
    "localhost",
    "net",
    "org",
    "test",
    # Pattern explanations use this acronym. A host whose only leaked label
    # is the product name is still removed as part of the full hostname.
    "wsus",
}
WELL_KNOWN_USERS = {
    "anonymous logon",
    "local service",
    "network service",
    "nt authority\\system",
    "system",
}

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SID_RE = re.compile(r"\bS-1-\d+(?:-\d+)+\b", re.IGNORECASE)
GUID_RE = re.compile(
    r"\b\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?\b"
)
# A trailing period is punctuation ("... at 203.0.113.25."). The lookbehind
# still refuses to start inside a longer dotted token such as a build number.
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
IPV6_RE = re.compile(r"(?<![0-9A-Za-z:])([0-9A-Fa-f:]{2,})(?![0-9A-Za-z:])")
FQDN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
)
USER_PATH_RE = re.compile(
    r"(?i)(?:[A-Za-z]:\\Users\\|/home/|/Users/)([^\\/:*?\"<>|\r\n]+)"
)
UNC_RE = re.compile(r"\\\\([A-Za-z0-9][A-Za-z0-9.-]{0,253})\\")
# A dotted account such as ada.example\AppData must not be read as DOMAIN\user.
DOMAIN_USER_RE = re.compile(
    r"(?<![A-Za-z0-9:\\.])([A-Za-z][A-Za-z0-9-]{0,14})\\([A-Za-z0-9._$-]{1,64})"
)
PATH_FOLDERS = {
    "all users",
    "appdata",
    "default",
    "default user",
    "desktop",
    "documents",
    "downloads",
    "local",
    "public",
    "roaming",
}
SECRET_RE = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|client_secret|api_key|authorization)\b"
    r"\s*[=:]\s*\"?([^\s,;\"']+)"
)


@dataclass
class RedactOptions:
    enabled: bool = True
    guids: bool = True
    ips: bool = True
    extra_hosts: list[str] = field(default_factory=list)
    extra_users: list[str] = field(default_factory=list)


@dataclass
class Span:
    start: int
    end: int
    priority: int
    category: str
    key: str
    original: str
    replacement: str = ""


class Session:
    """Redact identifiers with tokens that stay stable for one mapping."""

    def __init__(self, mapping: Mapping | None = None, options: RedactOptions | None = None) -> None:
        self.mapping = mapping or Mapping()
        self.options = options or RedactOptions()
        self.forced_hosts: set[str] = set()
        self.short_hosts: dict[str, str] = {}
        self.extra_users: set[str] = set()
        for host in self.options.extra_hosts:
            self.observe_host(host)
        for user in self.options.extra_users:
            self.observe_user(user)

    def observe_host(self, value: str | None) -> None:
        if not value or not self.options.enabled:
            return
        text = value.strip().rstrip(".")
        if not text:
            return
        try:
            ipaddress.ip_address(text)
            return
        except ValueError:
            pass
        if "." in text and self._valid_fqdn(text):
            key = text.casefold()
            self.forced_hosts.add(key)
            self._note_host_labels(key)
            return
        self._register_short(text, text.casefold())

    def observe_user(self, value: str | None) -> None:
        if not value or not self.options.enabled:
            return
        text = value.strip()
        if not text or text.casefold() in WELL_KNOWN_USERS:
            return
        if "\\" in text or "@" in text or text.upper().startswith("S-1-"):
            return
        if len(text) >= 3:
            self.extra_users.add(text)

    def redact(self, text: str) -> str:
        if not text or not self.options.enabled:
            return text
        spans = self._spans(text)
        chosen = _resolve(spans)
        chosen.sort(key=lambda item: item.start)
        for span in chosen:
            span.replacement = self.mapping.token(span.category, span.key, span.original)
        output = text
        for span in reversed(chosen):
            output = output[: span.start] + span.replacement + output[span.end :]
        return output

    def reveal(self, text: str) -> str:
        return self.mapping.reveal(text)

    def _spans(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for match in SECRET_RE.finditer(text):
            value = match.group(1)
            if value.startswith("LS_"):
                continue
            start, end = match.span(1)
            spans.append(Span(start, end, 100, "SECRET", value, text[start:end]))
        for match in USER_PATH_RE.finditer(text):
            name = match.group(1).strip(" .")
            if not name or name.casefold() in PATH_FOLDERS:
                continue
            start, end = match.span(1)
            self.extra_users.add(name)
            spans.append(Span(start, end, 90, "USER", name.casefold(), text[start:end]))
        for match in EMAIL_RE.finditer(text):
            original = match.group(0)
            local, domain = original.split("@", 1)
            spans.append(Span(match.start(), match.end(), 80, "EMAIL", original.casefold(), original))
            if len(local) >= 4 and local.casefold() not in STOPWORDS:
                self.extra_users.add(local)
            self._note_domain(domain)
        for match in SID_RE.finditer(text):
            original = match.group(0)
            spans.append(Span(match.start(), match.end(), 70, "SID", original.upper(), original))
        if self.options.guids:
            for match in GUID_RE.finditer(text):
                original = match.group(0)
                key = original.strip("{}").upper()
                spans.append(Span(match.start(), match.end(), 60, "GUID", key, original))
        if self.options.ips:
            for match in IPV6_RE.finditer(text):
                original = match.group(1)
                if original.count(":") < 2:
                    continue
                try:
                    parsed = ipaddress.ip_address(original)
                except ValueError:
                    continue
                if not isinstance(parsed, ipaddress.IPv6Address):
                    continue
                spans.append(Span(match.start(1), match.end(1), 55, "IPV6", parsed.compressed, original))
            for match in IPV4_RE.finditer(text):
                original = match.group(0)
                try:
                    parsed = ipaddress.ip_address(original)
                except ValueError:
                    continue
                if not isinstance(parsed, ipaddress.IPv4Address):
                    continue
                spans.append(Span(match.start(), match.end(), 50, "IPV4", str(parsed), original))
        for match in UNC_RE.finditer(text):
            host = match.group(1).rstrip(".")
            start, end = match.span(1)
            category, key = self._classify_dns(host)
            if category == "HOST":
                self._note_host_labels(key)
            spans.append(Span(start, end, 45, category, key, text[start:end]))
        for match in DOMAIN_USER_RE.finditer(text):
            domain, user = match.group(1), match.group(2)
            if domain.casefold() in {"nt"} or user.casefold() in PATH_FOLDERS:
                continue
            if f"{domain}\\{user}".casefold() in WELL_KNOWN_USERS:
                continue
            d_start, d_end = match.span(1)
            u_start, u_end = match.span(2)
            spans.append(Span(d_start, d_end, 40, "DOMAIN", domain.casefold(), text[d_start:d_end]))
            self.extra_users.add(user)
            spans.append(Span(u_start, u_end, 40, "USER", user.casefold(), text[u_start:u_end]))
        for match in FQDN_RE.finditer(text):
            name = match.group(0)
            if not self._valid_fqdn(name):
                continue
            category, key = self._classify_dns(name)
            if category == "HOST":
                self._note_host_labels(key)
            else:
                self._note_domain(key)
            spans.append(Span(match.start(), match.end(), 30, category, key, name))
        for user in sorted(self.extra_users, key=len, reverse=True):
            pattern = re.compile(
                rf"(?<![A-Za-z0-9._%+-]){re.escape(user)}(?![A-Za-z0-9._%+-])(?!@)",
                re.IGNORECASE,
            )
            for match in pattern.finditer(text):
                spans.append(Span(match.start(), match.end(), 85, "USER", user.casefold(), match.group(0)))
        for label, host_key in self.short_hosts.items():
            pattern = re.compile(
                rf"(?<![A-Za-z0-9-]){re.escape(label)}(?![A-Za-z0-9.-])",
                re.IGNORECASE,
            )
            for match in pattern.finditer(text):
                spans.append(Span(match.start(), match.end(), 20, "HOST", host_key, match.group(0)))
        return spans

    def _valid_fqdn(self, name: str) -> bool:
        labels = name.rstrip(".").split(".")
        if len(labels) < 2:
            return False
        if labels[-1].casefold() in FILE_TLDS:
            return False
        return all(1 <= len(label) <= 63 for label in labels)

    def _classify_dns(self, name: str) -> tuple[str, str]:
        key = name.casefold().rstrip(".")
        labels = key.split(".")
        if key in self.forced_hosts or len(labels) >= 3:
            return "HOST", key
        return "DOMAIN", key

    def _note_host_labels(self, host_key: str) -> None:
        labels = host_key.split(".")
        if labels:
            self._register_short(labels[0], host_key)
        if len(labels) >= 3:
            parent = ".".join(labels[1:])
            if "." in parent:
                self._note_domain(parent)

    def _note_domain(self, domain: str) -> None:
        key = domain.casefold().rstrip(".")
        if self._valid_fqdn(key):
            return

    def _register_short(self, label: str, host_key: str) -> None:
        key = label.casefold().strip(".")
        if len(key) < 4 or key in STOPWORDS:
            return
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,30}", key):
            return
        self.short_hosts.setdefault(key, host_key.casefold())


def _resolve(spans: list[Span]) -> list[Span]:
    ordered = sorted(spans, key=lambda item: (-item.priority, -(item.end - item.start), item.start))
    chosen: list[Span] = []
    for span in ordered:
        if span.end <= span.start:
            continue
        if any(not (span.end <= other.start or span.start >= other.end) for other in chosen):
            continue
        chosen.append(span)
    return chosen


def find_leaks(text: str, mapping: Mapping) -> list[str]:
    """Return original identifiers that are still visible in ``text``."""
    if not text:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for entry in mapping.entries:
        original = entry["original"]
        if _visible(original, text) and original not in seen:
            seen.add(original)
            found.append(original)
        if entry["category"] in {"HOST", "DOMAIN", "EMAIL"}:
            for label in re.split(r"[@.]", original):
                label = label.strip("{}")
                if len(label) < 4 or label.casefold() in COMMON_LABELS:
                    continue
                if _visible(label, text) and label not in seen:
                    seen.add(label)
                    found.append(label)
    return found


def _visible(original: str, text: str) -> bool:
    if len(original) >= 8 or "@" in original or original.upper().startswith("S-1-") or _is_ip(original):
        return original.casefold() in text.casefold()
    return re.search(
        rf"(?<![A-Za-z0-9]){re.escape(original)}(?![A-Za-z0-9])",
        text,
        re.IGNORECASE,
    ) is not None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True