
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ghascompliance.policies.models.severities import SeverityLevelEnum


@dataclass
class PolicyBase:
    # Make sure the feature is enabled
    enabled: bool = True
    # Base severity
    severity: SeverityLevelEnum = SeverityLevelEnum.ERROR
    # List of identifier to match against
    ids: List[str] = field(default_factory=list)
    ids_warnings: List[str] = field(default_factory=list)
    ids_ignores: List[str] = field(default_factory=list)



@dataclass
class ThreatModel:
    # Policy file to use
    uses: str
    # List of repositories that this policy should be applied to
    repositories: Optional[List[str]] = None


@dataclass
class PolicyV3:
    version: str = "3"
    name: str = "Policy"
    
    threatmodels: Dict[str, ThreatModel]= field(default_factory=dict)

    codescanning: PolicyBase = PolicyBase() 
    supplychain: PolicyBase = PolicyBase() 
    secertscanning: PolicyBase = PolicyBase()

    reporting: dict = field(default_factory=dict)


