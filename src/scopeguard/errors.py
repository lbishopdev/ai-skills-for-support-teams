"""Exceptions. Each carries a short code, never the data that caused it."""


class PolicyViolation(Exception):
    """A rule was broken. `code` is safe to log; it never contains the offending value."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class NoManifest(PolicyViolation):
    """The skill has no manifest, so it has no permissions at all (default deny)."""

    def __init__(self):
        super().__init__("no_manifest")


class ManifestError(PolicyViolation):
    """The manifest exists but is malformed or asks for something not allowed."""

    def __init__(self, detail: str):
        super().__init__("invalid_manifest")
        self.detail = detail
