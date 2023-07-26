import os
import logging
import yaml
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from ghastoolkit import Repository
from ghascompliance.octokit.octokit import Octokit

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
    """Make sure the feature is enabled."""

    enabled: bool = True
    """Required to be enabled"""

    name: str = "CodeScanningPolicy"
    """Name"""

    severity: SeverityLevelEnum = SeverityLevelEnum.ERROR
    """Base severity"""

    ids: List[str] = field(default_factory=list)
    """List of identifier to match against"""
    ids_warnings: List[str] = field(default_factory=list)
    ids_ignores: List[str] = field(default_factory=list)

    names: List[str] = field(default_factory=list)
    """The name of an alert"""

    cwes: List[str] = field(default_factory=list)
    """CWE IDs"""

    owasp: List[str] = field(default_factory=list)
    """OWASP Top 10"""

    tools: List[str] = field(default_factory=list)
    """Tools Names"""
    tools_required: List[str] = field(default_factory=list)
    """Required Tools"""

    remediate: RemediationPolicy = field(default_factory=RemediationPolicy)
    """Remediation Policy"""

    def __post_init__(self):
        if isinstance(self.severity, str):
            self.severity = SeverityLevelEnum.load(self.severity)


@dataclass
class SupplyChainPolicy:
    """Make sure the feature is enabled."""

    enabled: bool = True
    """Required to be enabled"""

    severity: SeverityLevelEnum = SeverityLevelEnum.HIGH
    """Base severity"""

    names: List[str] = field(default_factory=list)
    """List of package names / PURL to match against"""
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
    remediate: RemediationPolicy = field(default_factory=RemediationPolicy)

    def __post_init__(self):
        if isinstance(self.severity, str):
            self.severity = SeverityLevelEnum.load(self.severity)


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
    remediate: RemediationPolicy = field(default_factory=RemediationPolicy)

    def __post_init__(self):
        if isinstance(self.severity, str):
            self.severity = SeverityLevelEnum.load(self.severity)


@dataclass
class Display:
    """Displays Settings."""

    detailed: bool = False
    """Detailed display setting"""
    pr_summary: bool = True
    """Pull Request summary setting"""

    @staticmethod
    def load(data: Any) -> "Display":
        """Load Display."""
        if isinstance(data, bool):
            return Display(detailed=True) if data else Display()
        elif isinstance(data, dict):
            return loadDict(Display, data)
        return Display()


@dataclass
class Policy:
    """Policy model."""

    version: str = "3"

    """Name of the Policy"""
    name: str = "Policy"

    """ Displays all information in the output log"""
    display: Display = field(default_factory=Display)

    """Default Code Scanning Policy"""
    codescanning: Union[CodeScanningPolicy, List[CodeScanningPolicy]] = field(
        default_factory=CodeScanningPolicy
    )

    """Default Supply Chain Policy"""
    supplychain: SupplyChainPolicy = field(default_factory=SupplyChainPolicy)

    """Default Secret Scanning Policy"""
    secretscanning: SecretScanningPolicy = field(default_factory=SecretScanningPolicy)

    def __post_init__(self):
        # display
        self.display = Display.load(self.display)
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

        Octokit.debug(f"Loading policy from path :: {path}")
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

    """Languages"""
    languages: Optional[List[str]] = None

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

    version: str = "3"
    """Version of the PolicyEngine"""

    name: str = "Policy"
    """Name of the Policy"""

    display: Display = field(default_factory=Display)
    """ Displays all information in the output log"""

    threatmodels: Dict[str, ThreatModel] = field(default_factory=dict)
    """ Threat Models """

    codescanning: Union[CodeScanningPolicy, List[CodeScanningPolicy]] = field(
        default_factory=CodeScanningPolicy
    )
    """Default Code Scanning Policy"""

    supplychain: SupplyChainPolicy = field(default_factory=SupplyChainPolicy)
    """Default Supply Chain Policy"""

    secretscanning: SecretScanningPolicy = field(default_factory=SecretScanningPolicy)
    """Default Secret Scanning Policy"""

    plugins: Dict[str, Any] = field(default_factory=dict)
    """Plugins"""

    def __post_init__(self):
        # display
        self.display = Display.load(self.display)

        # threatmodels
        if self.threatmodels:
            for k, v in self.threatmodels.items():
                self.threatmodels[k] = loadDict(ThreatModel, v)

        # plugins
        if self.plugins:
            self.plugins = {}
            logger.warning(f"Plugins are currently not supported")

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

    def getPolicy(self, repository: Repository) -> Policy:
        """Find the Policy based on threatmodels or default policy"""
        repo = f"{repository.owner}/{repository.repo}"

        for name, tm in self.threatmodels.items():
            if tm.matches(repo) and tm.policy:
                Octokit.debug(f"Found policy by repository name :: {repo}")
                return tm.policy
            elif name == repo and tm.policy:
                Octokit.debug(f"Found policy by ThreatModel name :: {name}")
                return tm.policy

        default = Policy(
            name="default",
            display=self.display,
            codescanning=self.codescanning,
            supplychain=self.supplychain,
            secretscanning=self.secretscanning,
        )
        Octokit.debug("Using default Policy")

        return default
