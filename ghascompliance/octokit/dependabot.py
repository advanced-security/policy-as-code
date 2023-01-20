import os
import json
import requests
import urllib.parse
from string import Template
from ghascompliance.octokit.octokit import GitHub, OctoRequests, Octokit


class Dependencies(OctoRequests):
    def __init__(self, github: GitHub):
        super().__init__(github=github)
        # Update the headers for the Dependabot Preview API
        self.headers["Accept"] = "application/vnd.github.hawkgirl-preview+json"

        self.dependencies = []
        self.alerts = []

        # get current file path
        self.query_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "graphql"
        )

        self.queries = {}
        # load queries
        for query in os.listdir(self.query_path):
            with open(os.path.join(self.query_path, query), "r") as f:
                query_name = query.split(".")[0]
                self.queries[query_name] = f.read()

    @staticmethod
    def createDependencyName(manager: str, dependency: str, version: str = None):
        """Create a dependency full name"""
        ret = manager.lower() + "://" + dependency.lower()
        if version:
            ret += "#" + version.lower()
        return ret

    def getOpenAlerts(self, response: dict = {}):
        """Get Open Security Dependencies Alerts"""

        # if dependencies are in a PR
        if self.github.inPullRequest():
            return self.getPRDependencies()[1]

        variables = {"owner": self.github.owner, "repo": self.github.repo}

        results = []
        retries = 0
        cursor = ""

        # Add pagination
        while retries < 3:
            # set cursor
            if cursor:
                variables["cursor"] = f'after: "{cursor}"'
            else:
                variables["cursor"] = ""

            query_template = self.queries.get("GetDependencyAlerts")
            query = Template(query_template).substitute(**variables)

            request = requests.post(
                self.github.get("api.graphql"),
                json={"query": query},
                headers=self.headers,
                timeout=30,
            )
            if request.status_code != 200:
                Octokit.warning(
                    "Query failed to run by returning code of {}. {}".format(
                        request.status_code, query
                    )
                )
                retries += 1
                continue
            retries = 0  # reset retries

            response = request.json()

            if response.get("errors"):
                Octokit.error(json.dumps(response))
                raise Exception("Query failed to run")

            data = (
                response.get("data", {})
                .get("repository", {})
                .get("vulnerabilityAlerts", {})
            )

            for alert_node in data.get("edges", []):
                results.append(alert_node.get("node", {}))

            if not data.get("pageInfo", {}).get("hasNextPage"):
                break
            cursor = data.get("pageInfo", {}).get("endCursor")

        if len(results) != data.get("totalCount"):
            Octokit.error(f"Total Count: {data.get('totalCount')} != {len(results)}")

        if retries == 3:
            raise Exception("Retries exceeded max limit")

        return results

    def getDependencies(self, response: dict = {}):
        """Get Open Dependencies

        https://docs.github.com/en/enterprise-cloud@latest/rest/licenses?apiVersion=2022-11-28#get-the-license-for-a-repository

        https://docs.github.com/en/graphql/reference/objects#repository
        https://docs.github.com/en/graphql/reference/objects#dependencygraphdependency
        https://docs.github.com/en/graphql/reference/objects#dependencygraphmanifestconnection
        """

        # if dependencies are in a PR
        if self.github.inPullRequest():
            return self.getPRDependencies()[0]

        variables = {"owner": self.github.owner, "repo": self.github.repo}

        query_template = self.queries.get("GetDependencyInfo")
        query = Template(query_template).substitute(**variables)

        retries = 0

        while retries < 3:
            # paginate through the results
            request = requests.post(
                self.github.get("api.graphql"),
                json={"query": query},
                headers=self.headers,
                timeout=30,
            )
            if request.status_code == 200:
                break
            retries += 1
            Octokit.debug(f"Retring GraphQL API: retry {retries}")

        if request.status_code != 200:
            Octokit.warning("Make sure that Dependency Graph is enabled")
            raise Exception(
                "Query failed to run by returning code of {}. {}".format(
                    request.status_code, query
                )
            )

        response = request.json()

        if response.get("errors"):
            Octokit.error(json.dumps(response, indent=2))
            raise Exception("Query failed to run")

        repo = response.get("data", {}).get("repository", {})
        # repo_name = repo.get('name')
        # repo_license = repo.get('licenseInfo', {}).get('name')

        results = self.processManifests(
            repo.get("dependencyGraphManifests", {}).get("edges", [])
        )

        self.dependencies = results
        return results

    def processManifests(self, manifests: list) -> list:
        """Process the manifests and return a list of dependencies"""
        results = []

        for manifest in manifests:
            manifest = manifest.get("node", {})
            manifest_path = manifest.get("filename")

            dependencies = manifest.get("dependencies", {}).get("edges", [])

            for dependency in dependencies:
                dependency = dependency.get("node", {})

                dependency_manager = dependency.get("packageManager", "NA").lower()

                dependency_name = dependency.get("packageName", "NA")
                dependency_repo = dependency.get("repository", {})
                dependency_requirement = (
                    dependency.get("requirements", "")
                    .replace("= ", "")
                    .replace("^ ", "")
                )

                dependency_license = (
                    dependency_repo.get("licenseInfo") if dependency_repo else {}
                )

                dependency_license_name = (
                    dependency_license.get("name", "NA") if dependency_license else "NA"
                )

                Octokit.debug(f" > {dependency_name} == {dependency_license_name}")

                dependency_maintenance = []
                for dep_maintenance in [
                    "isArchived",
                    "isDisabled",
                    "isEmpty",
                    "isLocked",
                ]:
                    if dependency_repo and dependency_repo.get(dep_maintenance, False):
                        dependency_maintenance.append(
                            dep_maintenance.replace("is", "", 1).lower()
                        )

                is_organization: bool = None
                if dependency_repo:
                    is_organization = dependency_repo.get("isInOrganization")

                full_name = Dependencies.createDependencyName(
                    dependency_manager, dependency_name, dependency_requirement
                )

                results.append(
                    {
                        "name": dependency_name,
                        "full_name": full_name,
                        "manager": dependency_manager,
                        "manager_path": manifest_path,
                        "version": dependency_requirement,
                        "license": dependency_license_name,
                        "maintenance": dependency_maintenance,
                        "organization": is_organization,
                    }
                )

        return results

    def getPRDependencies(self) -> list:
        """Diff the dependencies against the base branch

        https://docs.github.com/en/enterprise-cloud@latest/rest/dependency-graph/dependency-review?apiVersion=2022-11-28#get-a-diff-of-the-dependencies-between-commits
        https://docs.github.com/en/enterprise-server@3.6/rest/dependency-graph/dependency-review#get-a-diff-of-the-dependencies-between-commits
        """
        pr_info = self.getPullRequestInfo()
        base = urllib.parse.quote(pr_info.get("base", {}).get("ref"))
        head = urllib.parse.quote(pr_info.get("head", {}).get("ref"))

        Octokit.debug(f"Creating diff for PR: `{base}...{head}`")

        full_url = self.github.get("api.rest") + self.format(
            "/repos/{owner}/{repo}/dependency-graph/compare/{base}...{head}",
            base=base,
            head=head,
        )
        diff_response = requests.get(full_url, headers=self.headers)
        if diff_response.status_code != 200:
            Octokit.warning(
                f"Failed to get diff information for dependencies: {base}...{head}"
            )
            return (self.dependencies, self.alerts)

        for dependency in diff_response.json():
            if dependency.get("change_type") == "added":
                name = dependency.get("name")
                manager = dependency.get("ecosystem")
                manager_path = dependency.get("manifest")
                version = dependency.get("version")
                license = dependency.get("license", "NA")
                # API might return null
                if not license:
                    license = "NA"

                self.dependencies.append(
                    {
                        "name": name,
                        # TODO: change to PURL format
                        "full_name": f"{manager}://{name}#{version}",
                        "manager": manager,
                        "manager_path": manager_path,
                        "version": version,
                        "license": license,
                    }
                )

                for vuln in dependency.get("vulnerabilities"):
                    self.alerts.append(
                        {
                            "createdAt": pr_info.get("created_at"),
                            "dismissReason": None,
                            "securityVulnerability": {
                                "package": {
                                    "name": name,
                                    "ecosystem": manager,
                                }
                            },
                            "securityAdvisory": {
                                "ghsaId": vuln.get("advisory_ghsa_id"),
                                "severity": vuln.get("severity"),
                            },
                        }
                    )

        return (self.dependencies, self.alerts)

    def getQuery(self, name: str) -> str:
        """Get the query for the given name"""
        return self.queries.get(name, "")


if __name__ == "__main__":
    # Dependency Analysis CLI tool
    # > export PYTHONPATH=$(pwd):$(pwd)/vendor
    # > python ./ghascompliance/octokit/dependabot.py
    github = GitHub(
        repository=os.environ.get("GITHUB_REPOSITORY"),
        token=os.environ.get("GITHUB_TOKEN"),
        ref=os.environ.get("GITHUB_REF"),
    )
    deps = Dependencies(github=github)
    dependencies = deps.getDependencies()

    print(f"Count of Dependencies: {len(dependencies)}")
    for index, dependency in enumerate(dependencies):
        name = dependency.get("name")
        version = dependency.get("version")
        manager = dependency.get("manager")
        license = dependency.get("license")

        print(f"{index:<4} [{manager:^12}] {name} == {version} ('{license}')")

    alerts = deps.getOpenAlerts()
    print(f"Count of Alerts: {len(alerts)}")

    for index, alert in enumerate(alerts):
        name = alert.get("securityVulnerability", {}).get("package", {}).get("name")
        manager = (
            alert.get("securityVulnerability", {}).get("package", {}).get("ecosystem")
        )
        alert_id = alert.get("securityAdvisory", {}).get("ghsaId")
        severity = alert.get("securityAdvisory", {}).get("severity")

        print(f"{index:<4} [{manager:^12}] {alert_id:<20} ({severity:^12}) <-> {name}")
