"""Log parsers. Each one returns the same LogEvent list."""

from logsieve.parsers.detect import iter_input_files, parse_path

__all__ = ["iter_input_files", "parse_path"]