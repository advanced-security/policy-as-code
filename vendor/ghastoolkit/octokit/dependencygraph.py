import json
import logging
from threading import main_thread
from typing import Any
import urllib.parse

from ghastoolkit.octokit.github import GitHub, Repository
from ghastoolkit.supplychain.advisories import Advisory
from ghastoolkit.supplychain.dependencyalert import DependencyAlert
from ghastoolkit.supplychain.dependencies import Dependencies, Dependency
from ghastoolkit.octokit.octokit import GraphQLRequest, Optional, RestRequest

logger = logging.getLogger("ghastoolkit.octokit.dependencygraph")


class DependencyGraph:
    def __init__(
        self,
        repository: Optional[Repository] = None,
        enable_graphql: bool = True,
        enable_clearlydefined: bool = False,
    ) -> None:
        self.repository = repository or GitHub.repository
        self.rest = RestRequest(repository)
        self.graphql = GraphQLRequest(repository)

        self.enable_graphql = enable_graphql
        self.enable_clearlydefined = enable_clearlydefined

    def getDependencies(self) -> Dependencies:
        """Get Dependencies"""
        deps = self.getDependenciesSbom()

        if self.enable_graphql:
            logger.debug("Enabled GraphQL Dependencies")
            graph_deps = self.getDependenciesGraphQL()

            deps.updateDependencies(graph_deps)

        if self.enable_clearlydefined:
            logger.debug("Applying ClearlyDefined on dependencies")
            deps.applyClearlyDefined()
        return deps

    def getDependenciesSbom(self) -> Dependencies:
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
                dep.license = package.get("licenseConcluded")
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
                dep.license = package.get("licenseConcluded")

            result.append(dep)

        return result

    def getDependenciesGraphQL(self) -> Dependencies:
        """Get Dependencies from GraphQL"""
        deps = Dependencies()
        data = self.graphql.query(
            "GetDependencyInfo",
            {"owner": self.repository.owner, "repo": self.repository.repo},
        )
        graph_manifests = (
            data.get("data", {})
            .get("repository", {})
            .get("dependencyGraphManifests", {})
        )
        logger.debug(
            f"Graph Manifests Total Count :: {graph_manifests.get('totalCount')}"
        )

        for manifest in graph_manifests.get("edges", []):
            node = manifest.get("node", {})
            logger.debug(f"Processing :: '{node.get('filename')}'")

            for dep in node.get("dependencies", {}).get("edges", []):
                dep = dep.get("node", {})
                license = None
                if dep.get("repository") and dep.get("repository", {}).get(
                    "licenseInfo"
                ):
                    license = (
                        dep.get("repository", {}).get("licenseInfo", {}).get("name")
                    )

                deps.append(
                    Dependency(
                        name=dep.get("packageName"),
                        manager=dep.get("packageManager"),
                        license=license,
                    )
                )

        return deps

    def getDependenciesInPR(self, base: str, head: str) -> Dependencies:
        """Get all the dependencies from a Pull Request"""
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
                    alert.get("severity"),
                    purl=dep.getPurl(False),
                    advisory=Advisory(
                        ghsa_id=alert.get("advisory_ghsa_id"),
                        severity=alert.get("severity"),
                        summary=alert.get("advisory_summary"),
                        url=alert.get("advisory_ghsa_url"),
                    ),
                )
                dep.alerts.append(dep_alert)

            dependencies.append(dep)

        return dependencies

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

    def submitSbom(self, sbom: dict[Any, Any]):
        """Submit SBOM"""
        self.rest.postJson(
            "/repos/{owner}/{repo}/dependency-graph/snapshots",
            sbom,
            expected=201,
        )
