from typing import Any
from ghascompliance.octokit.octokit import Octokit


class PolicyState:
    def __init__(self, name: str) -> None:
        self.name = name

        self.criticals = []
        self.errors = []
        self.warnings = []
        self.ignored = []

    def critical(self, data: Any, trigger_name: str = "na"):
        if isinstance(data, str):
            self.criticals.append({"msg": data, "trigger": trigger_name})
        else:
            Octokit.warning(f"Unknown critical type :: {type(data)}")

    def error(self, data: Any, trigger_name: str = "na"):
        if isinstance(data, str):
            self.errors.append({"msg": data, "trigger": trigger_name})
        else:
            Octokit.warning(f"Unknown error type :: {type(data)}")

    def warning(self, data: Any, trigger_name: str = "na"):
        if isinstance(data, str):
            self.warnings.append({"msg": data, "trigger": trigger_name})
        else:
            Octokit.warning(f"Unknown warning type :: {type(data)}")

    def ignore(self, data: Any, trigger_name: str = "na"):
        """Ignore State (mainly for testing)."""
        self.ignored.append({"msg": data, "trigger": trigger_name})

    def reset(self):
        """Reset PolicyState."""
        self.criticals = []
        self.errors = []
        self.warnings = []
        self.ignored = []
