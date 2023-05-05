import logging
from dataclasses import dataclass, field
from datetime import datetime
import re
from typing import Optional

from ghastoolkit.supplychain.dependencyalert import DependencyAlert
from ghastoolkit.supplychain.licensing import Licenses

logger = logging.getLogger("ghastoolkit.supplychain.dependencies")


@dataclass
class Dependency:
    name: str
    namespace: Optional[str] = None
    version: Optional[str] = None
    manager: Optional[str] = None
    path: Optional[str] = None
    qualifiers: dict[str, str] = field(default_factory=dict)

    # Licensing information
    licence: Optional[str] = None
    # Security Alerts
    alerts: list[DependencyAlert] = field(default_factory=list)

    def getPurl(self, version: bool = True) -> str:
        """Get PURL
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
        """Full Name of the Dependency"""
        if self.namespace:
            sep = "/"
            if self.manager == "maven":
                sep = ":"
            return f"{self.namespace}{sep}{self.name}"
        return self.name

    def __str__(self) -> str:
        return self.getPurl()

    def __repr__(self) -> str:
        return self.getPurl()


class Dependencies(list[Dependency]):
    def exportBOM(
        self,
        tool: str,
        path: str,
        sha: str = "",
        ref: str = "",
        version: str = "0.0.0",
        url: str = "",
    ) -> dict:
        """Create a dependency graph submission JSON payload for GitHub"""
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
        """Find Denied License"""
        regex_list = [re.compile(name_filter) for name_filter in licenses]
        return Dependencies(
            [
                dep
                for dep in self
                if any(regex.search(dep.licence or "NA") for regex in regex_list)
            ]
        )

    def findUnknownLicenses(
        self, licenses: Optional[list[str]] = None
    ) -> "Dependencies":
        licenses = licenses or ["NA", "NOASSERTION"]
        return self.findLicenses(licenses)

    def applyLicenses(self, licenses: Licenses):
        """Apply Linceses"""
        for i, dep in enumerate(self):
            if dep.licence:
                continue
            purl = dep.getPurl(version=False)
            dblicense = licenses.find(purl)
            if dblicense:
                dep.licence = " OR ".join(dblicense)
                self[i] = dep

    def contains(self, dependency: Dependency) -> bool:
        purl = dependency.getPurl(version=False)
        for dep in self:
            if dep.name == dependency.name or dep.getPurl(version=False) == purl:
                return True
        return False

    def find(self, name: str) -> Optional[Dependency]:
        """Find by name"""
        for dep in self:
            if dep.name == name or dep.fullname == name:
                return dep
        logger.debug(f"Unable to find by name :: {name}")

    def findPurl(self, purl: str) -> Optional[Dependency]:
        """Find by PURL"""
        purldep = Dependency.fromPurl(purl)
        for dep in self:
            if purldep.name == purldep.fullname or dep.fullname == dep.fullname:
                return dep
        logger.debug(f"Unable to find by PURL :: {purl}")

    def findNames(self, names: list[str]) -> "Dependencies":
        """Find by Name using wildcards"""
        regex_list = [re.compile(name_filter) for name_filter in names]
        return Dependencies(
            [dep for dep in self if any(regex.search(dep.name) for regex in regex_list)]
        )
