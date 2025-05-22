"""Dependency Graph Octokit."""

import json
import logging
from typing import Any, Dict
import urllib.parse

from semantic_version import Version

from ghastoolkit.errors import GHASToolkitError, GHASToolkitTypeError
from ghastoolkit.octokit.github import GitHub, Repository
from ghastoolkit.supplychain import (
    Advisory,
    Dependencies,
    Dependency,
    DependencyAlert,
    uniqueDependencies,
)
from ghastoolkit.octokit.enterprise import Organization
from ghastoolkit.octokit.octokit import GraphQLRequest, Optional, RestRequest
from ghastoolkit.utils.cache import Cache

logger = logging.getLogger("ghastoolkit.octokit.dependencygraph")


class DependencyGraph:
    """Dependency Graph API.

    This class is used to interact with the Dependency Graph API in GitHub.
    """

    def __init__(
        self,
        repository: Optional[Repository] = None,
        enable_graphql: bool = True,
        enable_clearlydefined: bool = False,
        cache: bool = False,
    ) -> None:
        """Initialise Dependency Graph.

        Arguments:
            repository: The repository to use. If not provided, it will use the current
                        repository in `GitHub`.
            enable_graphql: Enable GraphQL API. Defaults to True.
            enable_clearlydefined: Enable ClearlyDefined API. Defaults to False.
            cache: Enable caching. Defaults to False.

        """
        self.repository = repository or GitHub.repository
        self.rest = RestRequest(repository)
        self.graphql = GraphQLRequest(repository)

        self.enable_graphql = enable_graphql
        self.enable_clearlydefined = enable_clearlydefined

        self.cache_enabled = cache
        self.cache = Cache(store="dependencygraph")

    def getOrganizationDependencies(
        self, owner: Optional[str] = None
    ) -> Dict[Repository, Dependencies]:
        """Get Organization Dependencies for all repositories.

        This is done by iterating through all the repositories in the organization
        and getting the dependencies for each repository. This is done as there is no
        way to get all the dependencies for an organization in a single request.

        Arguments:
            owner: The owner of the organization. If not provided, it will use the current
                   owner of the repository.

        Returns:
            Dict[Repository, Dependencies]: A dictionary of repositories and their dependencies.
        """
        org = Organization(organization=owner or GitHub.owner)
        logger.debug(f"Processing organization :: {org}")

        deps: Dict[Repository, Dependencies] = {}

        repositories = org.getRepositories()
        logger.debug(f"Found `{len(repositories)}` repositories in organization")

        for repo in repositories:
            logger.debug(f"Processing repository :: {repo}")
            try:
                depgraph = DependencyGraph(repo, enable_graphql=self.enable_graphql)
                logger.debug(f"Using repository :: {depgraph.repository}")

                deps[repo] = depgraph.getDependenciesSbom()

                if depgraph.enable_graphql:
                    logger.debug("Enabled GraphQL Dependencies")
                    graph_deps = depgraph.getDependenciesGraphQL()

                    deps[repo].updateDependencies(graph_deps)
                    logger.debug("Updated dependencies with GraphQL")
            except Exception as err:
                logger.warning(f"Failed to get `{repo}` dependencies :: {err}")
                deps[repo] = Dependencies()

        self.rest = RestRequest(self.repository)
        return deps

    def getUniqueOrgDependencies(
        self,
        version: bool = False,
    ) -> Dependencies:
        """Create a unique list of dependencies, this is useful for merging multiple lists for example
        from an organization.

        Arguments:
            version: If True, include the version in the unique list. Defaults to False.
        """
        return uniqueDependencies(self.getOrganizationDependencies(), version=version)

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
        """Get Dependencies from SBOM.

        If cache is enabled, it will use the cached dependencies if they exist.
        If not, it will download the SBOM and cache it.
        """
        cache_key = self.rest.repository.__str__()

        if self.cache_enabled:
            cache = self.cache.read(cache_key, file_type="spdx.json")
            if cache:
                logger.debug(f"Using cached dependencies for `{self.rest.repository}`")
                data = json.loads(cache)
                return Dependencies.loadSpdxSbom(data)
            else:
                logger.debug(
                    f"Cache not found for {self.repository.repo}, downloading SBOM"
                )

        logger.debug(f"Downloading SBOM for {self.repository}")
        spdx_bom = self.exportBOM()

        if self.cache_enabled:
            logger.debug(f"Caching dependencies for {self.repository.repo}")
            self.cache.write(cache_key, spdx_bom, file_type="spdx.json")

        return Dependencies.loadSpdxSbom(spdx_bom)

    def getDependenciesGraphQL(self, dependencies_count: int = 100) -> Dependencies:
        """Get Dependencies from GraphQL.

        This functions requests each manifest file in the repository and the
        dependencies associated with it. It then paginates through both the manifests
        and dependencies.

        This is done to avoid the timeout errors in the GraphQL API when requesting
        large projects with many manifests and dependencies.
        """
        deps = Dependencies()

        if self.cache_enabled:
            cache_key = self.rest.repository.__str__()
            cache = self.cache.read(cache_key, file_type="graphql.json")
            if cache:
                logger.debug(f"Using cached dependencies for `{self.rest.repository}`")
                data = json.loads(cache)
                return self._parseGraphQL(data)

        # Build up a single list of dependencies
        graphql_data = {}

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
                if not graph_manifests.get("edges"):
                    logger.debug("No more manifests to be processed")
                    break

                for manifest in graph_manifests.get("edges", []):
                    node = manifest.get("node", {})

                    manifestfile = node.get("filename") or node.get("blobPath")
                    logger.debug(f"Processing :: '{manifestfile}'")

                    dependencies = node.get("dependencies", {})

                    if graphql_data.get(manifestfile):
                        graphql_data[manifestfile].update(dependencies)
                    else:
                        graphql_data[manifestfile] = dependencies

                    # Pagination
                    has_next_page = dependencies.get("pageInfo", {}).get(
                        "hasNextPage", False
                    )
                    if has_next_page:
                        dependencies_cursor = f'after: "{dependencies.get("pageInfo", {}).get("endCursor")}"'
                    else:
                        dependencies_cursor = ""

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

        if self.cache_enabled:
            logger.debug(f"Caching dependencies for {self.repository.repo}")
            self.cache.write(cache_key, graphql_data, file_type="graphql.json")

        return self._parseGraphQL(graphql_data)

    def getDependenciesInPR(self, base: str, head: str) -> Dependencies:
        """Get all the dependencies from a Pull Request.

        Arguments:
            base: The base branch of the Pull Request.
            head: The head branch of the Pull Request.
        Returns:
            Dependencies: A list of dependencies.

        """

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
                logger.warning("Package URL is not present, skipping...")
                logger.warning(f"Package :: {depdata}")
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

    def exportBOM(self) -> Dict:
        """Download / Export DependencyGraph SBOM.

        https://docs.github.com/en/rest/dependency-graph/sboms#export-a-software-bill-of-materials-sbom-for-a-repository
        """
        logger.debug(f"Exporting SBOM for {self.repository}")
        result = self.rest.get("/repos/{owner}/{repo}/dependency-graph/sbom")
        if result:
            return result

        raise GHASToolkitTypeError(
            "Failed to download SBOM",
            docs="https://docs.github.com/en/rest/dependency-graph/sboms#export-a-software-bill-of-materials-sbom-for-a-repository",
            permissions=['"Contents" repository permissions (read)'],
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

        Arguments:
            dependencies: The dependencies to submit.
            tool: The tool used to generate the dependencies.
            path: The path to the dependencies file.
            sha: The SHA of the commit.
            ref: The reference of the commit.
            version: The version of the dependencies.
            url: The URL of the dependencies file.

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

    def _parseGraphQL(self, data: Dict[str, Any]) -> Dependencies:
        """Parse GraphQL data.

        Arguments:
            data: The data to parse.

        Returns:
            Dependencies: A list of dependencies.
        """
        deps = Dependencies()

        for manifest, dependencies in data.items():
            for dep in dependencies.get("edges", []):
                dep = dep.get("node", {})
                license = None
                repository = None

                if dep.get("repository"):
                    if dep.get("repository", {}).get("licenseInfo"):
                        license = (
                            dep.get("repository", {}).get("licenseInfo", {}).get("name")
                        )
                    if dep.get("repository", {}).get("nameWithOwner"):
                        repository = dep.get("repository", {}).get("nameWithOwner")

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
                        path=manifest,
                    )
                )

        return deps
