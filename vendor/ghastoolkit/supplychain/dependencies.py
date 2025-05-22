import os
import json
import logging

from datetime import datetime
import re
from typing import Optional, Union, Dict

from ghastoolkit.octokit.github import Repository
from ghastoolkit.supplychain.dependency import Dependency
from ghastoolkit.supplychain.licensing import NO_LICENSES, Licenses

logger = logging.getLogger("ghastoolkit.supplychain.dependencies")


class Dependencies:
    """Set-like collection of Dependencies with list compatibility."""

    def __init__(self, iterable=None):
        """Initialize with an optional iterable."""
        self._dependencies = set()
        if iterable:
            for dep in iterable:
                self.add(dep)

    def add(self, dependency: Dependency, repository: Repository = None):
        """Add a dependency to the set."""
        self._dependencies.add(dependency)

        if repository:
            # Find and add repo
            for dep in self:
                if dep.name == dependency.name or dep.fullname == dependency.fullname:
                    dep.repositories.add(repository)
                    self.add(dep)
                    return

    def append(self, dependency: Dependency):
        """Append is an alias for `.add`, for backwards compatibility."""
        self.add(dependency)

    def extend(self, dependencies: "Dependencies"):
        """Extends Dependencies with another list of Dependencies."""
        self._dependencies.update(dependencies._dependencies)

    def remove(self, dependency: Dependency):
        """Remove a dependency from the set."""
        if dependency in self._dependencies:
            self._dependencies.remove(dependency)
        else:
            raise KeyError(f"Dependency {dependency} not found in the collection.")

    def pop(self, value: Union[str, int, Dependency]) -> Dependency:
        """Pop allows you to remove an element from the set and return it."""
        if isinstance(value, int):
            logger.warning("Index-based access is deprecated. Use iteration instead.")
            raise Exception("Index-based access is deprecated. Use iteration instead.")
        elif isinstance(value, str):
            for dep in self._dependencies:
                if dep.name == value or dep.fullname == value:
                    self.remove(dep)
                    return dep
        else:
            if value in self._dependencies:
                self.remove(value)
                return value
            else:
                raise KeyError(f"Dependency {value} not found in the collection.")

    def __iter__(self):
        """Iterator protocol support."""
        return iter(self._dependencies)

    def __len__(self):
        """Return count of dependencies."""
        return len(self._dependencies)

    def __contains__(self, dependency: Dependency) -> bool:
        """Check if dependency is in the collection."""
        return dependency in self._dependencies

    def __getitem__(self, key):
        """Support for index-based access for backward compatibility."""
        if isinstance(key, int):
            logger.warning("Index-based access is deprecated. Use iteration instead.")
            raise Exception("Index-based access is deprecated. Use iteration instead.")
        # If it's a dependency object, return the actual instance from the set
        for dep in self._dependencies:
            if dep == key:
                return dep
        raise KeyError(f"Dependency {key} not found")

    def __setitem__(self, key, value):
        """Support for index-based setting for backward compatibility."""
        if isinstance(key, int):
            # This is trickier since sets don't have indexes
            # We'll remove the old item at that position and add the new one
            items = list(self._dependencies)
            self._dependencies.remove(items[key])
            self._dependencies.add(value)
        else:
            # Not supported
            raise TypeError("Setting with non-integer indices not supported")

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

    @staticmethod
    def loadSpdx(
        path: str,
    ) -> "Dependencies":
        """Load a SPDX file into the Dependencies list."""
        if not os.path.exists(path):
            raise ValueError(f"File does not exist: {path}")
        if not os.path.isfile(path):
            raise ValueError(f"Path is not a file: {path}")

        with open(path, "r") as file:
            data = json.load(file)

        return Dependencies.loadSpdxSbom(data)

    @staticmethod
    def loadSpdxSbom(
        data: dict,
    ) -> "Dependencies":
        """Load a SBOM into the Dependencies list."""
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary")

        result = Dependencies()

        for package in data.get("sbom", {}).get("packages", []):
            extref = False
            dep = Dependency("")
            for ref in package.get("externalRefs", []):
                if ref.get("referenceType", "") == "purl":
                    dep = Dependency.fromPurl(ref.get("referenceLocator"))
                    extref = True
                else:
                    logger.warning(f"Unknown external reference :: {ref}")

            # if get find a PURL or not
            if extref:
                dep.license = package.get("licenseConcluded")
            else:
                name = package.get("name", "").lower()
                # manager ':'
                if ":" in name:
                    dep.manager, name = name.split(":", 1)

                # HACK: Maven / NuGet
                if dep.manager in ["maven", "nuget"]:
                    if "." in name:
                        dep.namespace, name = name.rsplit(".", 1)
                # Namespace '/'
                elif "/" in package:
                    dep.namespace, name = name.split("/", 1)

                dep.name = name
                dep.version = package.get("versionInfo")
                dep.license = package.get("licenseConcluded")

            result.append(dep)
        return result

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

    def contains(self, dependency: Dependency, version: bool = False) -> bool:
        """Contains the dependency.

        Arguments:
            dependency: Dependency to check
            version: Check the version as well

        Returns:
            bool: True if the dependency is in the list
        """
        purl = dependency.getPurl(version=version)
        for dep in self:
            if dep.getPurl(version=version) == purl:
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

    def findDirectDependencies(self) -> "Dependencies":
        """Find all the direct dependencies."""
        return Dependencies([dep for dep in self if dep.isDirect()])


def uniqueDependencies(
    dependencies: Dict[Repository, Dependencies],
    version: bool = False,
) -> Dependencies:
    """Create a unique list of dependencies, this is useful for merging multiple lists for example
    from an organization.

    Arguments:
        dependencies: List of dependencies to merge
        version: Check the version as well

    Returns:
        Dependencies: Unique list of dependencies
    """
    unique_deps = Dependencies()

    for repo, deps in dependencies.items():
        for dep in deps:
            unique_deps.add(dep, repo)

    return unique_deps
