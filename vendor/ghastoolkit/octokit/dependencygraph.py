import logging
from dataclasses import dataclass, field
from datetime import datetime
import re
from ghastoolkit.octokit.github import GitHub, Repository

from ghastoolkit.octokit.octokit import GraphQLRequest, Optional, RestRequest

logger = logging.getLogger("ghastoolkit.octokit.dependencygraph")


@dataclass
class Dependency:
    name: str
    namespace: Optional[str] = None
    version: Optional[str] = None
    manager: Optional[str] = None
    path: Optional[str] = None
    qualifiers: dict[str, str] = field(default_factory=list)

    licence: Optional[str] = None

    def getPurl(self, version: bool = True) -> str:
        """Get PURL
        https://github.com/package-url/purl-spec
        """
        result = f"pkg:"
        if self.manager:
            result += f"{self.manager}/"
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

    def contains(self, dependency: Dependency) -> bool:
        purl = dependency.getPurl(version=False)
        for dep in self:
            if dep.name == dependency.name or dep.getPurl(version=False) == purl:
                return True
        return False

    def find(self, name: str) -> Optional[Dependency]:
        for dep in self:
            if dep.name == name or dep.fullname == name:
                return dep

    def findNames(self, names: list[str]) -> "Dependencies":
        """Find by Name using wildcards"""
        regex_list = [re.compile(name_filter) for name_filter in names]
        return Dependencies(
            [dep for dep in self if any(regex.search(dep.name) for regex in regex_list)]
        )


class DependencyGraph:
    def __init__(self, repository: Optional[Repository] = None) -> None:
        self.repository = repository or GitHub.repository
        self.rest = RestRequest(repository)
        self.graphql = GraphQLRequest(repository)

    def getDependencies(self) -> Dependencies:
        """Get Dependencies from SBOM"""
        result = Dependencies()
        spdx_bom = self.exportBOM()

        for package in spdx_bom.get("sbom", {}).get("packages", []):
            extref = False
            dep = Dependency("")
            for ref in package.get("externalRefs", []):
                if ref.get("referenceType"):
                    dep = Dependency.fromPurl(ref.get("referenceLocator"))
                    extref = True

            # if get find a PURL or not
            if extref:
                dep.licence = package.get("licenseConcluded")
            else:
                name = package.get("name", "")
                # manager ':'
                if ":" in name:
                    dep.manager, name = name.split(":", 1)
                # Namespace '/'
                if "/" in package:
                    dep.namespace, name = name.split("/", 1)

                dep.name = name
                dep.version = package.get("versionInfo")
                dep.licence = package.get("licenseConcluded")

            result.append(dep)

        return result

    def exportBOM(self) -> Dependencies:
        """Download / Export DependencyGraph SBOM"""
        return self.rest.get("/repos/{owner}/{repo}/dependency-graph/sbom")

    def submitDependencies(
        self,
        dependencies: Dependencies,
        tool: str,
        path: str,
        sha: str = "",
        ref: str = "",
        version: str = "0.0.0",
        url: str = "",
    ):
        """
        https://docs.github.com/en/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#create-a-snapshot-of-dependencies-for-a-repository
        """
        self.rest.postJson(
            "/repos/{owner}/{repo}/dependency-graph/snapshots",
            dependencies.exportBOM(tool, path, sha, ref, version, url),
            expected=201,
        )
