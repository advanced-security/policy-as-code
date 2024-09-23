"""Dependency Graph Octokit."""

import logging
from typing import Any, Dict
import urllib.parse

from semantic_version import Version

from ghastoolkit.errors import GHASToolkitError, GHASToolkitTypeError
from ghastoolkit.octokit.github import GitHub, Repository
from ghastoolkit.supplychain.advisories import Advisory
from ghastoolkit.supplychain.dependencyalert import DependencyAlert
from ghastoolkit.supplychain.dependencies import Dependencies, Dependency
from ghastoolkit.octokit.octokit import GraphQLRequest, Optional, RestRequest

logger = logging.getLogger("ghastoolkit.octokit.dependencygraph")


class DependencyGraph:
    """Dependency Graph API."""

    def __init__(
        self,
        repository: Optional[Repository] = None,
        enable_graphql: bool = True,
        enable_clearlydefined: bool = False,
    ) -> None:
        """Initialise Dependency Graph."""
        self.repository = repository or GitHub.repository
        self.rest = RestRequest(repository)
        self.graphql = GraphQLRequest(repository)

        self.enable_graphql = enable_graphql
        self.enable_clearlydefined = enable_clearlydefined

    def getOrganizationDependencies(self) -> Dict[Repository, Dependencies]:
        """Get Organization Dependencies."""
        deps: Dict[Repository, Dependencies] = {}

        repositories = self.rest.get("/orgs/{org}/repos")
        if not isinstance(repositories, list):
            raise Exception("Invalid organization")

        for repo in repositories:
            repo = Repository.parseRepository(repo.get("full_name"))
            logger.debug(f"Processing repository :: {repo}")
            try:
                self.rest = RestRequest(repo)

                deps[repo] = self.getDependenciesSbom()
            except Exception as err:
                logger.warning(f"Failed to get dependencies :: {err}")
                deps[repo] = Dependencies()

        self.rest = RestRequest(self.repository)
        return deps

    def getDependencies(self) -> Dependencies:
        """Get Dependencies."""
        if GitHub.isEnterpriseServer():
            if not self.enable_clearlydefined:
                logger.warning(
                    "Enterprise Server does not support licensing information"
                )
            # enterprise: 3.8+ use SBOM API
            if GitHub.server_version >= Version("3.9.0"):
                logger.info("Using SBOM API to resolve dependencies (GHES 3.9+)")
                deps = self.getDependenciesSbom()
            # enterprise: 3.7+ use GraphQL API
            elif GitHub.server_version >= Version("3.6.0"):
                logger.warning("Using GraphQL API to resolve dependencies (GHES 3.6+)")
                deps = self.getDependenciesGraphQL()
            else:
                raise GHASToolkitError("Enterprise Server version must be >= 3.6.0")
        else:
            # cloud: download SBOM
            deps = self.getDependenciesSbom()

        if self.enable_graphql:
            logger.debug("Enabled GraphQL Dependencies")
            graph_deps = self.getDependenciesGraphQL()

            deps.updateDependencies(graph_deps)

        if self.enable_clearlydefined:
            logger.info("Using ClearlyDefined API to resolve dependency licenses")
            deps.applyClearlyDefined()
        return deps

    def getDependenciesSbom(self) -> Dependencies:
        """Get Dependencies from SBOM."""
        result = Dependencies()
        spdx_bom = self.exportBOM()

        for package in spdx_bom.get("sbom", {}).get("packages", []):
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

    def getDependenciesGraphQL(self, dependencies_count: int = 100) -> Dependencies:
        """Get Dependencies from GraphQL.

        This functions requests each manifest file in the repository and the
        dependencies associated with it. It then paginates through both the manifests
        and dependencies.

        This is done to avoid the timeout errors in the GraphQL API when requesting
        large projects with many manifests and dependencies.
        """
        deps = Dependencies()

        manifests = True
        manifests_cursor = ""
        dependencies_cursor = ""

        while manifests:
            # Query a single manifest at a time
            data = self.graphql.query(
                "GetDependencyInfo",
                {
                    "owner": self.repository.owner,
                    "repo": self.repository.repo,
                    "manifests_cursor": manifests_cursor,
                    "dependencies_first": dependencies_count,
                    "dependencies_cursor": dependencies_cursor,
                },
            )

            graph_manifests = (
                data.get("data", {})
                .get("repository", {})
                .get("dependencyGraphManifests", {})
            )
            logger.debug(f"Processing :: '{graph_manifests.get('totalCount')}'")

            # Runs at least once
            has_next_page = True

            while has_next_page:
                for manifest in graph_manifests.get("edges", []):
                    node = manifest.get("node", {})
                    dependencies = node.get("dependencies", {})
                    logger.debug(f"Processing :: '{node.get('filename')}'")

                    # Pagination
                    has_next_page = dependencies.get("pageInfo", {}).get(
                        "hasNextPage", False
                    )
                    if has_next_page:
                        dependencies_cursor = f'after: "{dependencies.get("pageInfo", {}).get("endCursor")}"'
                    else:
                        dependencies_cursor = ""

                    for dep in dependencies.get("edges", []):
                        dep = dep.get("node", {})
                        license = None
                        repository = None

                        if dep.get("repository"):
                            if dep.get("repository", {}).get("licenseInfo"):
                                license = (
                                    dep.get("repository", {})
                                    .get("licenseInfo", {})
                                    .get("name")
                                )
                            if dep.get("repository", {}).get("nameWithOwner"):
                                repository = dep.get("repository", {}).get(
                                    "nameWithOwner"
                                )

                        version = dep.get("requirements")
                        if version:
                            version = version.replace("= ", "")

                        deps.append(
                            Dependency(
                                name=dep.get("packageName"),
                                manager=dep.get("packageManager"),
                                version=version,
                                license=license,
                                repository=repository,
                            )
                        )

                if has_next_page:
                    logger.debug(
                        f"Re-run and fetch next data page :: {manifests_cursor} ({dependencies_cursor})"
                    )

                    data = self.graphql.query(
                        "GetDependencyInfo",
                        {
                            "owner": self.repository.owner,
                            "repo": self.repository.repo,
                            "manifests_cursor": manifests_cursor,
                            "dependencies_first": dependencies_count,
                            "dependencies_cursor": dependencies_cursor,
                        },
                    )
                    graph_manifests = (
                        data.get("data", {})
                        .get("repository", {})
                        .get("dependencyGraphManifests", {})
                    )

            # If there are no other manifest files, then we are done
            if graph_manifests.get("pageInfo", {}).get("hasNextPage"):
                cursor = graph_manifests.get("pageInfo", {}).get("endCursor")
                manifests_cursor = f'after: "{cursor}"' if cursor != "" else ""
                logger.debug(f"Cursor :: {manifests_cursor}")
            else:
                manifests = False
                manifests_cursor = ""
                logger.debug("No more manifests to be processed")

        return deps

    def getDependenciesInPR(self, base: str, head: str) -> Dependencies:
        """Get all the dependencies from a Pull Request."""

        if GitHub.isEnterpriseServer() and GitHub.server_version < Version("3.6.0"):
            raise GHASToolkitError("Enterprise Server version must be >= 3.6")

        dependencies = Dependencies()
        base = urllib.parse.quote(base, safe="")
        head = urllib.parse.quote(head, safe="")
        basehead = f"{base}...{head}"
        logger.debug(f"PR basehead :: {basehead}")

        results = self.rest.get(
            "/repos/{owner}/{repo}/dependency-graph/compare/{basehead}",
            {"basehead": basehead},
            expected=200,
        )

        if not results:
            logger.warning("Failed to get dependencies from Pull Request")
            logger.warning(
                "Make sure Advanced Security is enabled and token permissions are correct"
            )
            return dependencies

        for depdata in results:
            if depdata.get("change_type") == "removed":
                continue

            purl = depdata.get("package_url")
            if not purl or purl == "":
                logger.warn("Package URL is not present, skipping...")
                logger.warn(f"Package :: {depdata}")
                continue

            dep = Dependency.fromPurl(purl)
            dep.licence = depdata.get("license")

            for alert in depdata.get("vulnerabilities", []):
                dep_alert = DependencyAlert(
                    depdata.get("vulnerabilities").index(alert),
                    "open",
                    alert.get("severity"),
                    purl=dep.getPurl(False),
                    advisory=Advisory(
                        ghsa_id=alert.get("advisory_ghsa_id"),
                        severity=alert.get("severity"),
                        summary=alert.get("advisory_summary"),
                        url=alert.get("advisory_ghsa_url"),
                    ),
                    manifest=alert.get("manifest"),
                )
                dep.alerts.append(dep_alert)

            dependencies.append(dep)

        return dependencies

    def exportBOM(self) -> Dependencies:
        """Download / Export DependencyGraph SBOM.

        https://docs.github.com/en/rest/dependency-graph/sboms#export-a-software-bill-of-materials-sbom-for-a-repository
        """
        result = self.rest.get("/repos/{owner}/{repo}/dependency-graph/sbom")
        if result:
            return result

        raise GHASToolkitTypeError(
            "Failed to download SBOM",
            docs="https://docs.github.com/en/rest/dependency-graph/sboms#export-a-software-bill-of-materials-sbom-for-a-repository",
        )

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
        """Submit dependencies to GitHub Dependency Graph snapshots API.

        https://docs.github.com/en/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#create-a-snapshot-of-dependencies-for-a-repository
        """
        self.rest.postJson(
            "/repos/{owner}/{repo}/dependency-graph/snapshots",
            dependencies.exportBOM(tool, path, sha, ref, version, url),
            expected=201,
        )

    def submitSbom(self, sbom: dict[Any, Any]):
        """Submit SBOM."""
        self.rest.postJson(
            "/repos/{owner}/{repo}/dependency-graph/snapshots",
            sbom,
            expected=201,
        )
