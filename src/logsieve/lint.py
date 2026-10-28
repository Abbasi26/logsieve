"""Check pattern YAML before it is used: load errors, ids, sources, and self-tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from logsieve.errors import LogsieveError
from logsieve.models import LogEvent
from logsieve.patterns.matcher import LIBRARY_DIR, Pattern, load_pattern_file


@dataclass
class LintResult:
    files: int
    patterns: int
    problems: list[str]

    @property
    def ok(self) -> bool:
        return not self.problems


def _files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted([*target.glob("*.yaml"), *target.glob("*.yml")])
    raise LogsieveError(f"pattern path not found: {target}")


def _self_test(pattern: Pattern) -> bool:
    event = LogEvent(
        timestamp=None,
        severity="error",
        source_file="self-test",
        source_type="plain",
        message=pattern.self_test,
        provider=pattern.self_test_provider,
        event_id=pattern.self_test_event_id,
    )
    return pattern.matches(event, event.search_text())


def lint_patterns(targets: list[Path], *, against_builtin: bool = True) -> LintResult:
    """Return every problem found. A load error in one file does not stop the others."""
    problems: list[str] = []
    builtin_ids: set[str] = set()
    builtin_paths = {path.resolve() for path in LIBRARY_DIR.glob("*.yaml")}
    if against_builtin:
        for path in sorted(LIBRARY_DIR.glob("*.yaml")):
            builtin_ids.update(pattern.id for pattern in load_pattern_file(path))
    seen: dict[str, str] = {}
    files = 0
    count = 0
    for target in targets:
        for path in _files(target):
            files += 1
            try:
                patterns = load_pattern_file(path)
            except (LogsieveError, yaml.YAMLError) as exc:
                problems.append(f"{path.name}: does not load ({str(exc).splitlines()[0]})")
                continue
            is_builtin = path.resolve() in builtin_paths
            for pattern in patterns:
                count += 1
                where = f"{path.name}: {pattern.id}"
                if pattern.id in seen:
                    problems.append(f"{where}: id already used in {seen[pattern.id]}")
                elif pattern.id in builtin_ids and not is_builtin:
                    problems.append(f"{where}: id already used by the built-in library")
                seen.setdefault(pattern.id, path.name)
                bad = [source for source in pattern.sources if not source.startswith("https://")]
                if bad:
                    problems.append(f"{where}: source is not an https URL ({bad[0]})")
                if not pattern.explanation:
                    problems.append(f"{where}: explanation is empty")
                if not pattern.self_test:
                    problems.append(f"{where}: self_test is missing")
                elif not _self_test(pattern):
                    problems.append(f"{where}: self_test line does not match the pattern")
    return LintResult(files=files, patterns=count, problems=problems)
