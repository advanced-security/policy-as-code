import os
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

import yaml

from ghascompliance.policies.severities import SeverityLevelEnum


logger = logging.getLogger("ghascompliance.policies")


class PolicyConfig:
    base: str = os.getcwd()


def loadDict(clss, data) -> Any:
    modified_dict = {key.replace("-", "_"): value for key, value in data.items()}
    return clss(**modified_dict)


@dataclass
class RemediationPolicy:
    errors: Union[int, Dict[str, int]] = -1 
    warnings: Union[int, Dict[str, int]] = -1 
    all: Union[int, Dict[str, int]] = -1 


@dataclass
class CodeScanningPolicy:
    """Make sure the feature is enabled"""

    enabled: bool = True
    """Name"""
    name: str = "CodeScanningPolicy"

    """Base severity"""
    severity: SeverityLevelEnum = SeverityLevelEnum.ERROR

    """List of identifier to match against"""
    ids: List[str] = field(default_factory=list)
    ids_warnings: List[str] = field(default_factory=list)
    ids_ignores: List[str] = field(default_factory=list)

    """The name of an alert"""
    names: List[str] = field(default_factory=list)

    """CWE IDs"""
    cwes: List[str] = field(default_factory=list)

    """OWASP Top 10"""
    owasp: List[str] = field(default_factory=list)

    """Tools Names"""
    tools: List[str] = field(default_factory=list)
    """Required Tools"""
    tools_required: List[str] = field(default_factory=list)

    """Remediation Policy"""
    remediate: RemediationPolicy = RemediationPolicy()

@dataclass
class SupplyChainPolicy:
    """Make sure the feature is enabled"""

    enabled: bool = True

    """Base severity"""
    severity: SeverityLevelEnum = SeverityLevelEnum.HIGH

    """List of package names / PURL to match against"""
    names: List[str] = field(default_factory=list)
    names_warnings: List[str] = field(default_factory=list)
    names_ignores: List[str] = field(default_factory=list)

    advisories: List[str] = field(default_factory=list)
    advisories_ignores: List[str] = field(default_factory=list)

    licenses: List[str] = field(default_factory=list)

    """Unknown Licenses"""
    licenses_unknown: bool = False

    """Licenses to warn only on"""
    licenses_warnings: List[str] = field(default_factory=list)

    """Licenses to ignore"""
    licenses_ignores: List[str] = field(default_factory=list)

    """Remediation Policy"""
    remediate: RemediationPolicy = RemediationPolicy()

@dataclass
class SecretScanningPolicy:
    """Make sure the feature is enabled"""

    enabled: bool = True

    """Base severity"""
    severity: SeverityLevelEnum = SeverityLevelEnum.ALL

    """List of identifier to match against"""
    ids: List[str] = field(default_factory=list)
    ids_warnings: List[str] = field(default_factory=list)
    ids_ignores: List[str] = field(default_factory=list)

    """Push Protection"""
    push_protection: bool = False

    """Remediation Policy"""
    remediate: RemediationPolicy = RemediationPolicy()

@dataclass
class Policy:
    """Version of the PolicyEngine"""

    version: str = "3"

    """Name of the Policy"""
    name: str = "Policy"

    """ Displays all information in the output log"""
    display: bool = False

    """Default Code Scanning Policy"""
    codescanning: Union[
        CodeScanningPolicy, List[CodeScanningPolicy]
    ] = CodeScanningPolicy()

    """Default Supply Chain Policy"""
    supplychain: SupplyChainPolicy = SupplyChainPolicy()

    """Default Secret Scanning Policy"""
    secretscanning: SecretScanningPolicy = SecretScanningPolicy()

    def __post_init__(self):
        # default policies
        if isinstance(self.codescanning, (dict, list)):
            if isinstance(self.codescanning, list):
                new_codescanning = []
                for csp in self.codescanning:
                    new_codescanning.append(loadDict(CodeScanningPolicy, csp))
                self.codescanning = new_codescanning
            else:
                self.codescanning = loadDict(CodeScanningPolicy, self.codescanning)

        if isinstance(self.supplychain, dict):
            self.supplychain = loadDict(SupplyChainPolicy, self.supplychain)

        if isinstance(self.secretscanning, dict):
            self.secretscanning = loadDict(SecretScanningPolicy, self.secretscanning)

    @staticmethod
    def loadPolicy(path: str) -> "Policy":
        if not os.path.exists(path) and not path.endswith(".yml"):
            logger.error(f"Failed to load path :: {path}")
            raise Exception(f"Failed to load policy path")

        with open(path, "r") as handle:
            data = yaml.safe_load(handle)

        print(f" >>> {path}")
        return Policy(**data)


@dataclass
class ThreatModel:
    """ThreadModel"""

    """Policy file to use"""
    uses: Optional[str] = None

    """List of repositories that this policy should be applied to"""
    repositories: Optional[List[str]] = None

    """Owner"""
    owner: Optional[str] = None

    """Policy"""
    policy: Optional[Policy] = None

    def __post_init__(self):
        if self.uses:
            print(f"Loading Policy :: {self.uses}")
            path = os.path.join(PolicyConfig.base, self.uses)
            # TODO path traversal?
            self.policy = Policy.loadPolicy(path)

    def matches(self, repository: str) -> bool:
        if self.owner:
            owner, _ = repository.split("/", 1)
            if self.owner == owner:
                return True
        elif self.repositories and repository in self.repositories:
            return True
        return False


@dataclass
class PolicyV3:
    """Policy as Code v3"""

    """Version of the PolicyEngine"""
    version: str = "3"

    """Name of the Policy"""
    name: str = "Policy"

    """ Displays all information in the output log"""
    display: bool = False

    """ Threat Models """
    threatmodels: Dict[str, ThreatModel] = field(default_factory=dict)

    """Default Code Scanning Policy"""
    codescanning: Union[
        CodeScanningPolicy, List[CodeScanningPolicy]
    ] = CodeScanningPolicy()

    """Default Supply Chain Policy"""
    supplychain: SupplyChainPolicy = SupplyChainPolicy()

    """Default Secret Scanning Policy"""
    secretscanning: SecretScanningPolicy = SecretScanningPolicy()

    """Plugins"""
    plugins: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.threatmodels:
            for k, v in self.threatmodels.items():
                self.threatmodels[k] = loadDict(ThreatModel, v)
        if self.plugins:
            self.plugins = {}
            logger.debug(f"Plugins are currently not supported")

        # default policies
        if isinstance(self.codescanning, (dict, list)):
            if isinstance(self.codescanning, list):
                new_codescanning = []
                for csp in self.codescanning:
                    new_codescanning.append(loadDict(CodeScanningPolicy, csp))
                self.codescanning = new_codescanning
            else:
                self.codescanning = loadDict(CodeScanningPolicy, self.codescanning)

        if isinstance(self.supplychain, dict):
            self.supplychain = loadDict(SupplyChainPolicy, self.supplychain)

        if isinstance(self.secretscanning, dict):
            self.secretscanning = loadDict(SecretScanningPolicy, self.secretscanning)

    @staticmethod
    def loadRootPolicy(path: str) -> "PolicyV3":
        if not os.path.exists(path) and not path.endswith(".yml"):
            logger.error(f"Failed to load path :: {path}")
            raise Exception(f"Failed to load policy path")

        with open(path, "r") as handle:
            data = yaml.safe_load(handle)

        return PolicyV3(**data)

    def getPolicy(self, repository: str) -> Policy:
        """Find the Policy based on threatmodels or default policy"""
        for name, tm in self.threatmodels.items():
            if tm.matches(repository) and tm.policy:
                return tm.policy
            elif name == repository and tm.policy:
                return tm.policy

        default = Policy(
            name="default",
            display=self.display,
            codescanning=self.codescanning,
            supplychain=self.supplychain,
            secretscanning=self.secretscanning,
        )

        return default
