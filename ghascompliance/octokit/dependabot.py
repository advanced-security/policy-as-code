import os
import json
import requests
from string import Template
from ghascompliance.octokit.octokit import GitHub, OctoRequests, Octokit


class Dependencies(OctoRequests):
    def __init__(self, github: GitHub):
        super().__init__(github=github)
        # Update the headers for the Dependabot Preview API
        self.headers["Accept"] = "application/vnd.github.hawkgirl-preview+json"

        self.dependencies = []

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

        variables = {"owner": self.github.owner, "repo": self.github.repo}

        query_template = self.queries.get("GetDependencyInfo")
        query = Template(query_template).substitute(**variables)

        while True:
            # paginate through the results
            request = requests.post(
                self.github.get("api.graphql"),
                json={"query": query},
                headers=self.headers,
                timeout=30,
            )
            if request.status_code == 200:
                break
            Octokit.debug(f"Retring GraphQL API: retry {retry}")

        if request.status_code != 200:
            raise Exception(
                "Query failed to run by returning code of {}. {}".format(
                    request.status_code, query
                )
            )

        response = request.json()

        if response.get("errors"):
            Octokit.error(json.dumps(response, indent=2))
            raise Exception("Query failed to run")

        results = []

        repo = response.get("data", {}).get("repository", {})
        # repo_name = repo.get('name')
        # repo_license = repo.get('licenseInfo', {}).get('name')

        manifests = repo.get("dependencyGraphManifests", {}).get("edges", [])

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

        self.dependencies = results
        return results

    def getQuery(self, name: str) -> str:
        """Get the query for the given name"""
        return self.queries.get(name, "")


if __name__ == "__main__":
    # Dependency Analysis CLI tool
    # > export PYTHONPATH=$(pwd)
    # > python ./ghascompliance/octokit/dependabot.py
    github = GitHub(
        repository=os.environ.get("GITHUB_REPOSITORY"),
        token=os.environ.get("GITHUB_TOKEN"),
    )
    dependencies = Dependencies(github=github)
    # dependencies.getDependencies()

    alerts = dependencies.getOpenAlerts()

    print(f"Count of Dependencies: {len(dependencies.dependencies)}")
    for index, dependency in enumerate(dependencies.dependencies):
        name = dependency.get("name")
        version = dependency.get("version")
        manager = dependency.get("manager")
        license = dependency.get("license")

        print(f"{index:<4} [{manager:^12}] {name} == {version} ('{license}')")

    print(f"Count of Dependencies: {len(alerts)}")
    for index, alert in enumerate(alerts):
        name = alert.get("securityVulnerability", {}).get("package", {}).get("name")
        manager = (
            alert.get("securityVulnerability", {}).get("package", {}).get("ecosystem")
        )
        alert_id = alert.get("securityAdvisory", {}).get("ghsaId")
        severity = alert.get("securityAdvisory", {}).get("severity")
        print(f"{index:<4} [{manager:^12}] {alert_id:<20} ({severity:^12}) <-> {name}")
