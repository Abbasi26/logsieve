class LogsieveError(Exception):
    """Expected failure with a process exit code."""

    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code