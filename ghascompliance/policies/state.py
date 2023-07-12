from typing import Any
from ghascompliance.octokit.octokit import Octokit


class PolicyState:
    def __init__(self, name: str) -> None:
        self.name = name
        self.errors = []
        self.warnings = []

    def error(self, data: Any):
        if isinstance(data, str):
            self.errors.append(data)
        else:
            Octokit.warning(f"Unknown error type :: {type(data)}")

    def warning(self, data: Any):
        if isinstance(data, str):
            self.warnings.append(data)
        else:
            Octokit.warning(f"Unknown error type :: {type(data)}")
