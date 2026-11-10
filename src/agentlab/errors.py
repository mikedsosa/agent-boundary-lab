"""Denied-path errors. Details are fixed phrases, never file contents or tokens."""


class BoundaryDenied(Exception):
    def __init__(self, reason: str, detail: str) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}")
