import os
import json
from datetime import datetime
from typing import *

from ghastoolkit import GitHub 
from ghastoolkit.octokit.codescanning import CodeScanning
from ghastoolkit.octokit.dependencygraph import DependencyGraph, Dependencies
from ghastoolkit.octokit.dependabot import Dependabot
from ghastoolkit.octokit.secretscanning import SecretScanning

from ghascompliance.policy import Policy
from ghascompliance.octokit import Octokit


__HERE__ = os.path.dirname(os.path.realpath(__file__))
GRAPHQL_QUERIES = [
    os.path.join(__HERE__, "octokit", "graphql")
]

class Checks:
    def __init__(
        self,
        policy: Policy,
        display: bool = False,
        debugging: bool = False,
        results_path: str = ".compliance",
        caching: bool = True,
    ):
        self.policy = policy

        self.display = display
        self.debugging = debugging
        self.results = results_path

        self.caching = caching

        os.makedirs(self.results, exist_ok=True)

    def getResults(self, name: str, callback: Callable, file_type: str = "json"):
        path = os.path.join(self.results, name + "." + file_type)

        if self.caching and os.path.exists(path):
            Octokit.info("Using Cached content :: " + name)
            with open(path, "r") as handle:
                return json.load(handle)
        else:
            results = callback()
            self.writeResults(name, results, file_type=file_type)
            return results

    def writeResults(self, name: str, results: str, file_type: str = "json"):
        path = os.path.join(self.results, name + "." + file_type)
        if not self.debugging:
            Octokit.debug("Skipping writing results to disk")
        elif file_type == "json":
            Octokit.info("Writing results to disk :: " + path)
            with open(path, "w") as handle:
                json.dump(results, handle, indent=2)
        else:
            Octokit.warning("Unsupported write type :: " + file_type)

    def checkCodeScanning(self):
        # Code Scanning results
        Octokit.createGroup("Code Scanning Results")
        code_scanning_errors = 0

        codescanning = CodeScanning()

        alerts = codescanning.getAlerts("open")

        Octokit.info("Total Code Scanning Alerts :: " + str(len(alerts)))

        if GitHub.repository.isInPullRequest():
            Octokit.info("Code Scanning Alerts from Pull Request (alert diff)")

        self.writeResults("code-scanning", alerts)

        for alert in alerts:
            severity = alert.get("rule", {}).get("severity")
            rule_name = alert.get("rule", {}).get("description")

            ids = []
            # Rule ID
            ids.append(alert.get("rule", {}).get("id"))
            # TODO: CWE?

            names = []
            #  Rule Name
            names.append(rule_name)

            alert_creation_time = datetime.strptime(
                alert.get("created_at"), "%Y-%m-%dT%XZ"
            )

            if self.policy.checkViolation(
                severity,
                technology="codescanning",
                names=names,
                ids=ids,
                creation_time=alert_creation_time,
            ):
                if self.display:
                    error_format = "{tool_name} - {creation_time} - {rule_name}"

                    location = alert.get("most_recent_instance", {}).get("location", {})

                    Octokit.error(
                        error_format.format(
                            tool_name=alert.get("tool", {}).get("name"),
                            rule_name=rule_name,
                            creation_time=alert_creation_time,
                        ),
                        file=location.get("path"),
                        line=location.get("start_line"),
                        col=location.get("start_column"),
                    )

                code_scanning_errors += 1

        alerts_message = "Code Scanning violations :: {count}"
        Octokit.info(alerts_message.format(count=code_scanning_errors))

        Octokit.endGroup()

        return code_scanning_errors

    def checkDependabot(self):
        Octokit.createGroup("Dependabot Results")
        dependabot_errors = 0

        # Alerts
        dependabot = Dependabot(GitHub.repository)
        # Load the GraphQL Queries from the repo
        dependabot.graphql.loadQueries(GRAPHQL_QUERIES)
        alerts = dependabot.getAlerts()

        # Dependencies
        depgraph = DependencyGraph()
        dependencies = depgraph.getDependencies()

        Octokit.info("Total Dependabot Alerts :: " + str(len(alerts)))

        if GitHub.repository.isInPullRequest():
            Octokit.info("Dependabot Alerts from Pull Request")

        for alert in alerts:
            package = alert.get("securityVulnerability", {}).get("package", {})
            name = package.get("name", "N/A")

            if alert.get("dismissReason") is not None:
                Octokit.debug(
                    "Skipping Dependabot alert :: {} - {} ".format(
                        name,
                        alert.get("dismissReason"),
                    )
                )
                continue

            # Find the dependency from the graph
            dependency = dependencies.find(name)
            
            if not dependency:
                Octokit.warning(f"Unable to find alert in DependencyGraph :: {name}")
                continue

            advisory = alert.get("securityAdvisory", {})
            severity = advisory.get("severity", "note").lower()
            full_name = dependency.fullname

            alert_creation_time = datetime.strptime(
                alert.get("createdAt"), "%Y-%m-%dT%XZ"
            )

            ids = []
            #  GitHub Advisory
            ids.append(advisory.get("ghsaId").lower())
            #  CWE support
            cwes = []
            for cwe in advisory.get("cwes", {}).get("edges", []):
                cwes.append(cwe.get("node", {}).get("cweId"))
            ids.extend(cwes)

            names = []
            #  maven://org.apache.commons
            names.append(name)

            if dependency:
                #  maven://org.apache.commons#1.0
                names.append(full_name)
            else:
                Octokit.debug(
                    "Dependency Graph to Dependabot alert match failed :: " + full_name
                )

            if self.policy.checkViolation(
                severity,
                "dependabot",
                names=names,
                ids=ids,
                creation_time=alert_creation_time,
            ):
                if self.display:
                    Octokit.error("Dependabot Alert :: {}".format(full_name))

                dependabot_errors += 1

        Octokit.info("Dependabot violations :: " + str(dependabot_errors))

        Octokit.endGroup()

        return dependabot_errors

    def checkDependencyLicensing(self):
        Octokit.createGroup(
            "Dependency Graph Results - Licensing",
            warning_prepfix="Dependency Graph Alert",
        )

        licensing_errors = 0

        # Dependencies
        depgraph = DependencyGraph()
        dependencies = depgraph.getDependencies()

        Octokit.info("Total Dependencies in Graph :: " + str(len(dependencies)))

        if GitHub.repository.isInPullRequest():
            Octokit.info("Dependencies from Pull Request")
            # TODO check this
        
        if not self.policy.policy and not self.policy.policy.get("licensing"):
            Octokit.debug("Skipping as licensing policy not set")
            return licensing_errors

        # Warnings (NA, etc)
        warnings = Dependencies()

        warnings_ids = self.policy.policy.get("licensing", {}).get("warnings", {}).get("ids", [])
        warnings_names = self.policy.policy.get("licensing", {}).get("warnings", {}).get("names", [])
 
        warnings.extend(dependencies.findLicenses(warnings_ids))
        warnings.extend(dependencies.findNames(warnings_names))

        for warning in warnings:
            Octokit.warning(f" > {warning} - {warning.licence}")

            if self.display:
                Octokit.warning(
                    "Dependency License Warning :: {} = {}".format(
                        warning, warning.licence
                    )
                )
        
        ignores_ids = self.policy.policy.get("licensing", {}).get("ingores", {}).get("ids", [])
        ignores_names = self.policy.policy.get("licensing", {}).get("ingores", {}).get("names", [])

        # License Checks (GPL, etc)
        violations = Dependencies()

        violations_ids = self.policy.policy.get("licensing", {}).get("conditions", {}).get("ids", [])
        violations_names = self.policy.policy.get("licensing", {}).get("conditions", {}).get("names", [])
 
        violations.extend(dependencies.findLicenses(violations_ids))
        violations.extend(dependencies.findNames(violations_names))

        for violation in violations:
            if violation.name in ignores_names or violation.licence in ignores_ids:
                Octokit.debug(f"Skipping {violation} because in ignore list...")
                continue

            Octokit.error(
                "Dependency Graph Alert :: {} = {}".format(
                    violation, violation.licence
                )
            )

            licensing_errors += 1

        Octokit.info("Dependency Graph violations :: " + str(licensing_errors))

        Octokit.endGroup()

        return licensing_errors

    def checkDependencies(self):
        Octokit.createGroup(
            "Dependency Graph",
            warning_prepfix="Dependency Graph Alert",
        )

        dependency_errors = 0

        depgraph = DependencyGraph()
        dependencies = depgraph.getDependencies()

        Octokit.info("Total Dependency Graph :: " + str(len(dependencies)))
        if GitHub.repository.isInPullRequest():
            Octokit.info("Dependencies from Pull Request")

        policy = self.policy.policy.get("dependencies", {}).get("warnings", {})

        for dependency in dependencies:
            ids = []
            names = []
            # manager + name
            names.append(dependency.fullname)
            # manager + name + version
            names.append(dependency.getPurl())

            #  none is set to just check if the name or pattern is discovered
            if self.policy.checkViolation("none", "dependencies", names=names, ids=ids):
                Octokit.error(
                    "Dependency Graph Alert :: {}".format(
                        dependency.fullname
                    )
                )
                dependency_errors += 1

        Octokit.info("Dependency Graph violations :: " + str(dependency_errors))

        Octokit.endGroup()

        return dependency_errors

    def checkSecretScanning(self):
        # Secret Scanning Results
        Octokit.createGroup("Secret Scanning Results")

        secrets_errors = 0

        secretscanning = SecretScanning()

        alerts = secretscanning.getAlerts("open")

        Octokit.info("Total Secret Scanning Alerts :: " + str(len(alerts)))
        if GitHub.repository.isInPullRequest():
            Octokit.info("Secret Scanning Alerts from Pull Request")

        for alert in alerts:

            alert_creation_time = datetime.strptime(
                alert.get("created_at"), "%Y-%m-%dT%XZ"
            )

            ids = []
            ids.append(alert.get("secret_type"))

            if self.policy.checkViolation(
                "critical", "secretscanning", ids=ids, creation_time=alert_creation_time
            ):
                if self.display:
                    Octokit.info("Unresolved Secret - {secret_type}".format(**alert))

            secrets_errors += 1

        Octokit.info("Secret Scanning violations :: " + str(secrets_errors))

        Octokit.endGroup()

        return secrets_errors

    def isRemediationPolicy(self, technology: str = "general") -> bool:
        return self.policy.policy.get(technology, {}).get("remediate") is not None
