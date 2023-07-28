import os
import logging
import yaml
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from ghastoolkit import Repository
from yaml import load
from ghascompliance.octokit.octokit import Octokit

from ghascompliance.policies.severities import SeverityLevelEnum


logger = logging.getLogger("ghascompliance.policies")


class PolicyConfig:
    base: str = os.getcwd()


def loadDict(clss, data) -> Any:
    """Load data from a dict into a provided class."""
    if isinstance(data, clss):
        return data
    modified_dict = {key.replace("-", "_"): value for key, value in data.items()}
    return clss(**modified_dict)


def loadDictList(clss, data: list) -> List[Any]:
    """Load data from a list of dicts into a list of provided class."""
    result = []
    for i in data:
        result.append(loadDict(clss, i))
    return result


@dataclass
class RemediationPolicy:
    """RemediationPolicy."""

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
    """Required Dependency Graph and Dependabot to be enabled"""

    security_updates: bool = False
    """Required Security Updates to be enabled"""

    severity: SeverityLevelEnum = SeverityLevelEnum.HIGH
    """Base severity"""

    names: List[str] = field(default_factory=list)
    """List of package names / PURL to match against"""
    names_warnings: List[str] = field(default_factory=list)
    names_ignores: List[str] = field(default_factory=list)

    advisories: List[str] = field(default_factory=list)
    advisories_ignores: List[str] = field(default_factory=list)

    licenses: List[str] = field(default_factory=list)
    """List of licenses"""
    licenses_unknown: bool = False
    """Unknown Licenses"""
    licenses_warnings: List[str] = field(default_factory=list)
    """Licenses to warn only on"""
    licenses_ignores: List[str] = field(default_factory=list)
    """Licenses to ignore"""

    remediate: RemediationPolicy = field(default_factory=RemediationPolicy)
    """Remediation Policy"""

    def __post_init__(self):
        if isinstance(self.severity, str):
            self.severity = SeverityLevelEnum.load(self.severity)


@dataclass
class SecretScanningPolicy:
    """Make sure the feature is enabled."""

    enabled: bool = True
    """Require Secret Scanning to be enabled"""
    push_protection: bool = False
    """Require Push Protection"""
    push_protection_warning: bool = True
    """Warn on Push Protection being disabled"""

    severity: SeverityLevelEnum = SeverityLevelEnum.ALL
    """Base severity"""

    ids: List[str] = field(default_factory=list)
    """List of identifiers to match against"""
    ids_warnings: List[str] = field(default_factory=list)
    """List of identifiers to match warnings against"""
    ids_ignores: List[str] = field(default_factory=list)
    """List of identifiers to match ignores against"""

    names: List[str] = field(default_factory=list)
    """List of secret display names"""

    remediate: RemediationPolicy = field(default_factory=RemediationPolicy)
    """Remediation Policy"""

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

    name: str = "Policy"
    """Name of the Policy"""

    display: Display = field(default_factory=Display)
    """ Displays all information in the output log"""

    codescanning: List[CodeScanningPolicy] = field(default_factory=list)
    """Default Code Scanning Policy"""

    supplychain: List[SupplyChainPolicy] = field(default_factory=list)
    """Default Supply Chain Policy"""

    secretscanning: List[SecretScanningPolicy] = field(default_factory=list)
    """Default Secret Scanning Policy"""

    def __post_init__(self):
        # display
        self.display = Display.load(self.display)

        # default policies
        # load code scanning policies
        if isinstance(self.codescanning, dict):
            self.codescanning = [loadDict(CodeScanningPolicy, self.codescanning)]
        elif isinstance(self.codescanning, list):
            if len(self.codescanning) != 0:
                self.codescanning = loadDictList(CodeScanningPolicy, self.codescanning)
            else:
                self.codescanning.append(CodeScanningPolicy())

        # load supply chain policies
        if isinstance(self.supplychain, dict):
            self.supplychain = [loadDict(SupplyChainPolicy, self.supplychain)]
        elif isinstance(self.supplychain, list):
            if len(self.supplychain) != 0:
                self.supplychain = loadDictList(SupplyChainPolicy, self.supplychain)
            else:
                self.supplychain.append(SupplyChainPolicy())

        # load secret scanning policies
        if isinstance(self.secretscanning, dict):
            self.secretscanning = [loadDict(SecretScanningPolicy, self.secretscanning)]
        elif isinstance(self.secretscanning, list):
            if len(self.secretscanning) != 0:
                self.secretscanning = loadDictList(
                    SecretScanningPolicy, self.secretscanning
                )
            else:
                self.secretscanning.append(SecretScanningPolicy())

    @staticmethod
    def loadPolicy(path: str) -> "Policy":
        """Load a policy from file path."""
        if not os.path.exists(path) and not path.endswith(".yml"):
            logger.error(f"Failed to load path :: {path}")
            raise Exception(f"Failed to load policy path")

        with open(path, "r") as handle:
            data = yaml.safe_load(handle)

        Octokit.debug(f"Loading policy from path :: {path}")
        return Policy(**data)


@dataclass
class ThreatModel:
    """ThreadModel."""

    uses: Optional[str] = None
    """Policy file to use"""

    repositories: Optional[List[str]] = None
    """List of repositories that this policy should be applied to"""

    owner: Optional[str] = None
    """Owner"""

    languages: Optional[List[str]] = None
    """Languages"""

    policy: Optional[Policy] = None
    """Policy"""

    def __post_init__(self):
        if self.uses:
            print(f"Loading Policy :: {self.uses}")
            path = os.path.join(PolicyConfig.base, self.uses)
            # TODO path traversal?
            self.policy = Policy.loadPolicy(path)

    def matches(self, repository: str) -> bool:
        """Check to see if the repository name ([owner/]repo) is in the ThreadModel."""
        if self.owner:
            owner, _ = repository.split("/", 1)
            if self.owner == owner:
                return True
        elif self.repositories and repository in self.repositories:
            return True
        return False


@dataclass
class PolicyV3:
    """Policy as Code v3."""

    version: str = "3"
    """Version of the PolicyEngine"""

    name: str = "Policy"
    """Name of the Policy"""

    display: Display = field(default_factory=Display)
    """ Displays all information in the output log"""

    threatmodels: Dict[str, ThreatModel] = field(default_factory=dict)
    """ Threat Models """

    codescanning: List[CodeScanningPolicy] = field(default_factory=list)
    """Default Code Scanning Policy"""

    supplychain: List[SupplyChainPolicy] = field(default_factory=list)
    """Default Supply Chain Policy"""

    secretscanning: List[SecretScanningPolicy] = field(default_factory=list)
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

        # > default policies
        # load code scanning policies
        if isinstance(self.codescanning, dict):
            self.codescanning = [loadDict(CodeScanningPolicy, self.codescanning)]
        elif isinstance(self.codescanning, list):
            if len(self.codescanning) != 0:
                self.codescanning = loadDictList(CodeScanningPolicy, self.codescanning)
            else:
                self.codescanning.append(CodeScanningPolicy())

        # load supply chain policies
        if isinstance(self.supplychain, dict):
            self.supplychain = [loadDict(SupplyChainPolicy, self.supplychain)]
        elif isinstance(self.supplychain, list):
            if len(self.supplychain) != 0:
                self.supplychain = loadDictList(SupplyChainPolicy, self.supplychain)
            else:
                self.supplychain.append(SupplyChainPolicy())

        # load secret scanning policies
        if isinstance(self.secretscanning, dict):
            self.secretscanning = [loadDict(SecretScanningPolicy, self.secretscanning)]
        elif isinstance(self.secretscanning, list):
            if len(self.secretscanning) != 0:
                self.secretscanning = loadDictList(
                    SecretScanningPolicy, self.secretscanning
                )
            else:
                self.secretscanning.append(SecretScanningPolicy())

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
