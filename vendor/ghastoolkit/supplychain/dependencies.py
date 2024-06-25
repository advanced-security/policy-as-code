import logging
from dataclasses import dataclass, field
from datetime import datetime
import re
from typing import Optional, Union

from ghastoolkit.octokit.github import Repository
from ghastoolkit.supplychain.dependencyalert import DependencyAlert
from ghastoolkit.supplychain.licensing import NO_LICENSES, Licenses

logger = logging.getLogger("ghastoolkit.supplychain.dependencies")


@dataclass
class Dependency:
    """Dependency."""

    name: str
    """Name of the Dependency"""
    namespace: Optional[str] = None
    """Namespace of the Dependency"""
    version: Optional[str] = None
    """Version of the Dependency"""
    manager: Optional[str] = None
    """Package Manager"""
    path: Optional[str] = None
    """Path to the Dependency"""
    qualifiers: dict[str, str] = field(default_factory=dict)
    """Qualifiers"""
    license: Optional[str] = None
    """License information"""
    alerts: list[DependencyAlert] = field(default_factory=list)
    """Security Alerts"""

    repository: Optional[Union[str, Repository]] = None
    """GitHub Repository for the dependency"""

    def __post_init__(self):
        # normalize manager
        if self.manager:
            self.manager = self.manager.lower()
        if self.repository and isinstance(self.repository, str):
            self.repository = Repository.parseRepository(self.repository)

    def getPurl(self, version: bool = True) -> str:
        """Create a PURL from the Dependency.

        https://github.com/package-url/purl-spec
        """
        result = f"pkg:"
        if self.manager:
            result += f"{self.manager.lower()}/"
        if self.namespace:
            result += f"{self.namespace}/"
        result += f"{self.name}"
        if version and self.version:
            result += f"@{self.version}"

        return result

    @staticmethod
    def fromPurl(purl: str) -> "Dependency":
        """Create a Dependency from a PURL."""
        dep = Dependency("")
        # version (at end)
        if "@" in purl:
            pkg, dep.version = purl.split("@", 1)
        else:
            pkg = purl

        slashes = pkg.count("/")
        if slashes == 0 and pkg.count(":", 1):
            # basic purl `npm:name`
            manager, dep.name = pkg.split(":", 1)
        elif slashes == 2:
            manager, dep.namespace, dep.name = pkg.split("/", 3)
        elif slashes == 1:
            manager, dep.name = pkg.split("/", 2)
        elif slashes > 2:
            manager, dep.namespace, dep.name = pkg.split("/", 2)
        else:
            raise Exception(f"Unable to parse PURL :: {purl}")

        if manager.startswith("pkg:"):
            _, dep.manager = manager.split(":", 1)
        else:
            dep.manager = manager

        return dep

    @property
    def fullname(self) -> str:
        """Full Name of the Dependency."""
        if self.namespace:
            sep = "/"
            if self.manager == "maven":
                sep = ":"
            return f"{self.namespace}{sep}{self.name}"
        return self.name

    def __str__(self) -> str:
        """To String (PURL)."""
        return self.getPurl()

    def __repr__(self) -> str:
        return self.getPurl()

    def __hash__(self) -> int:
        return hash(self.getPurl())


class Dependencies(list[Dependency]):
    """List of Dependencies."""

    def exportBOM(
        self,
        tool: str,
        path: str,
        sha: str = "",
        ref: str = "",
        version: str = "0.0.0",
        url: str = "",
    ) -> dict:
        """Create a dependency graph submission JSON payload for GitHub."""
        resolved = {}
        for dep in self:
            name = dep.name
            purl = dep.getPurl()
            resolved[name] = {"package_url": purl}

        data = {
            "version": 0,
            "sha": sha,
            "ref": ref,
            "job": {"correlator": tool, "id": tool},
            "detector": {"name": tool, "version": version, "url": url},
            "scanned": datetime.now().isoformat(),
            "manifests": {
                tool: {
                    "name": tool,
                    "file": {
                        "source_location": path,
                    },
                    "resolved": resolved,
                }
            },
        }
        return data

    def findLicenses(self, licenses: list[str]) -> "Dependencies":
        """Find dependencies with a given license."""
        regex_list = [re.compile(name_filter) for name_filter in licenses]
        return Dependencies(
            [
                dep
                for dep in self
                if any(regex.search(dep.license or "NA") for regex in regex_list)
            ]
        )

    def findUnknownLicenses(
        self, licenses: Optional[list[str]] = None
    ) -> "Dependencies":
        """Find all the dependencies with no licensing information."""
        licenses = licenses or NO_LICENSES
        return self.findLicenses(licenses)

    def applyLicenses(self, licenses: Licenses):
        """Given a list of licenses (Licenses) apply a license."""
        for i, dep in enumerate(self):
            if dep.license and dep.license not in NO_LICENSES:
                continue
            purl = dep.getPurl(version=False)
            dblicense = licenses.find(purl)
            if dblicense:
                dep.license = " OR ".join(dblicense)
                self[i] = dep

    def applyClearlyDefined(self):
        """Reachout to ClearlyDefinded API, get the licenses for a component, and update all the Dependencies."""
        from ghastoolkit.octokit.clearlydefined import ClearlyDefined

        clearly = ClearlyDefined()

        for i, dep in enumerate(self):
            if dep.license and dep.license not in NO_LICENSES:
                continue
            licenses = clearly.getLicenses(dep)
            if licenses:
                dep.license = " OR ".join(licenses)
                self[i] = dep

    def contains(self, dependency: Dependency) -> bool:
        """Contains the dependency."""
        purl = dependency.getPurl(version=False)
        for dep in self:
            if dep.name == dependency.name or dep.getPurl(version=False) == purl:
                return True
        return False

    def find(self, name: str) -> Optional[Dependency]:
        """Find by name."""
        for dep in self:
            if dep.name == name or dep.fullname == name:
                return dep
        logger.debug(f"Unable to find by name :: {name}")

    def findPurl(self, purl: str) -> Optional[Dependency]:
        """Find by PURL."""
        purldep = Dependency.fromPurl(purl)
        for dep in self:
            if purldep.name == purldep.fullname or dep.fullname == dep.fullname:
                return dep
        logger.debug(f"Unable to find by PURL :: {purl}")

    def findNames(self, names: list[str]) -> "Dependencies":
        """Find by Name using wildcards."""
        regex_list = [re.compile(name_filter) for name_filter in names]
        return Dependencies(
            [dep for dep in self if any(regex.search(dep.name) for regex in regex_list)]
        )

    def updateDependency(self, dependency: Dependency):
        """Update a dependency in our list with the incoming information."""
        for dep in self:
            if dependency.name == dep.name or dependency.fullname == dep.fullname:
                dep.__dict__.update(dependency.__dict__)
                # self[i] = new_dep
                break

    def updateDependencies(self, dependencies: "Dependencies"):
        """Update a list of dependencies."""
        for dep in dependencies:
            self.updateDependency(dep)
