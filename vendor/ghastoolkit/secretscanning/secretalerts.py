from dataclasses import dataclass, field
from typing import Optional

from ghastoolkit.octokit.octokit import OctoItem


@dataclass
class SecretAlert(OctoItem):
    number: int
    state: str

    created_at: str

    secret_type: str
    secret_type_display_name: str
    secret: str

    _locations: list[dict] = field(default_factory=list)
    _sha: Optional[str] = None

    @property
    def locations(self) -> list[dict]:
        """Get Alert locations (use cache or request from API)"""
        if not self._locations:
            from ghastoolkit.octokit.secretscanning import SecretScanning

            self._locations = SecretScanning().getAlertLocations(self.number)
        return self._locations

    @property
    def commit_sha(self) -> Optional[str]:
        """Get commit sha if present"""
        if self._sha is None:
            for loc in self.locations:
                if loc.get("type") == "commit":
                    self._sha = loc.get("details", {}).get("blob_sha")
                    break
        return self._sha

    def __str__(self) -> str:
        return f"SecretAlert({self.number}, '{self.secret_type}')"
