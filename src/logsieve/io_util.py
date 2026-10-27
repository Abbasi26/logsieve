from __future__ import annotations

from pathlib import Path


def read_text(path: Path) -> str:
    """Read a log file, including UTF-16 ConfigMgr logs that have no BOM."""
    data = path.read_bytes()
    if not data:
        return ""
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16")
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig")
    sample = data[:400]
    odd_nulls = sample[1::2].count(0) if len(sample) > 1 else 0
    if odd_nulls > len(sample) // 8:
        try:
            return data.decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8", errors="replace")