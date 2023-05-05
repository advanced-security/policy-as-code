from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from ghastoolkit.octokit.octokit import OctoItem
from ghastoolkit.supplychain.advisories import Advisory


@dataclass
class DependencyAlert(OctoItem):
    severity: str
    advisory: Advisory

    purl: str

    created_at: Optional[str] = None

    def __init_post__(self):
        if not self.created_at:
            self.created_at = datetime.now().strftime("%Y-%m-%dT%XZ")

    @property
    def cwes(self) -> list[str]:
        return self.advisory.cwes

    def createdAt(self) -> Optional[datetime]:
        if self.created_at:
            return datetime.strptime(self.created_at, "%Y-%m-%dT%XZ")

    def __str__(self) -> str:
        return f"DependencyAlert({self.advisory.ghsa_id}, {self.severity})"
