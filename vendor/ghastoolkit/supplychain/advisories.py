from dataclasses import dataclass, field
from typing import Optional
from ghastoolkit.octokit.octokit import OctoItem


@dataclass
class Advisory(OctoItem):
    ghsa_id: str
    severity: str

    summary: Optional[str] = None
    url: Optional[str] = None
    cwes: list[str] = field(default_factory=list)
