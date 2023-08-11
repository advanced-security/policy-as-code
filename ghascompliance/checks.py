import os
import json
from datetime import datetime
from typing import *

from ghastoolkit import (
    GitHub,
    CodeScanning,
    Dependencies,
    DependencyGraph,
    Dependabot,
    SecretScanning,
    Licenses,
)

from ghascompliance.policy import Policy
from ghascompliance.octokit import Octokit
from ghascompliance.octokit.summary import Summary


__HERE__ = os.path.dirname(os.path.realpath(__file__))
LICENSES = [os.path.join(__HERE__, "data", "clearlydefined.json")]
GRAPHQL_QUERIES = [os.path.join(__HERE__, "octokit", "graphql")]


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
        Summary.addHeader("Code Scanning Results", 2)
        code_scanning_violations_headers = [
            "Tool Name",
            "Rule Name",
            "Severity",
            "Alert Creation Time",
        ]
        code_scanning_violations = []

        codescanning = CodeScanning()

        if GitHub.repository.isInPullRequest():
            Octokit.info("Code Scanning Alerts from Pull Request (alert diff)")
            pr_base = (
                GitHub.repository.getPullRequestInfo().get("base", {}).get("ref", "")
            )
            alerts = codescanning.getAlertsInPR(pr_base)

        else:
            Octokit.debug(
                f"Code Scanning Alerts from reference :: {GitHub.repository.reference}"
            )
            alerts = codescanning.getAlerts("open", ref=GitHub.repository.reference)

        Octokit.info("Total Code Scanning Alerts :: " + str(len(alerts)))

        for alert in alerts:
            Octokit.debug(f"Processing Alert :: {alert} ({alert.severity})")
            severity = alert.severity
            rule_name = alert.description

            ids = []
            # Rule ID
            ids.append(alert.rule_id)
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
                tool_name = alert.get("tool", {}).get("name")
                code_scanning_violations.append(
                    [
                        tool_name,
                        rule_name,
                        severity,
                        alert_creation_time.strftime("%Y-%m-%dT%XZ"),
                    ]
                )
                if self.display:
                    error_format = "{tool_name} - {creation_time} - {rule_name}"

                    location = alert.get("most_recent_instance", {}).get("location", {})

                    Octokit.error(
                        error_format.format(
                            tool_name=tool_name,
                            rule_name=rule_name,
                            creation_time=alert_creation_time,
                        ),
                        file=location.get("path"),
                        line=location.get("start_line"),
                        col=location.get("start_column"),
                    )

        violation_count = len(code_scanning_violations)
        Octokit.info(f"Code Scanning violations :: {violation_count}")

        Octokit.endGroup()

        if violation_count == 0:
            Summary.addLine(f"{Summary.__ICONS__['check']} 0 Code Scanning violations")
        else:
            Summary.addLine(
                f"{Summary.__ICONS__['cross']} {violation_count} Code Scanning violation{'s' if violation_count > 1 else ''}"
            )

        if self.display and violation_count > 0:
            Summary.addCollapsed(
                Summary.formatTable(
                    code_scanning_violations_headers, code_scanning_violations
                ),
                summary=Summary.formatItalics("Code Scanning violations"),
            )

        return violation_count

    def checkDependabot(self):
        Octokit.createGroup("Dependabot Results")
        Summary.addHeader("Dependabot Results", 2)
        dependabot_violation_headers = [
            "GHSA ID",
            "CWEs",
            "Severity",
            "Alert Creation Time",
        ]
        dependabot_violations = []

        dependabot = Dependabot()
        # Load the GraphQL Queries from the repo
        dependabot.graphql.loadQueries(GRAPHQL_QUERIES)

        depgraph = DependencyGraph()

        if GitHub.repository.isInPullRequest():
            Octokit.info("Dependabot Alerts from Pull Request")
            pr_info = GitHub.repository.getPullRequestInfo()
            pr_base = pr_info.get("base", {}).get("ref", "")
            pr_head = pr_info.get("head", {}).get("ref", "")

            # note, need to use dep review API
            dependencies = depgraph.getDependenciesInPR(pr_base, pr_head)
            alerts = []
            for dep in dependencies:
                alerts.extend(dep.alerts)

        else:
            # Alerts
            alerts = dependabot.getAlerts()
            # Dependencies
            dependencies = depgraph.getDependencies()

        Octokit.info("Total Dependabot Alerts :: " + str(len(alerts)))

        for alert in alerts:
            if alert.get("dismissReason") is not None:
                Octokit.debug(
                    "Skipping Dependabot alert :: {} - {} ".format(
                        alert.purl,
                        alert.get("dismissReason"),
                    )
                )
                continue

            # Find the dependency from the graph
            dependency = dependencies.findPurl(alert.purl)

            if not dependency:
                Octokit.error(
                    f"Unable to find alert in DependencyGraph :: {alert.purl}"
                )
                continue

            severity = alert.severity.lower()

            if alert.createdAt():
                alert_creation_time = alert.createdAt()
            else:
                alert_creation_time = datetime.now()

            ids = []
            #  GitHub Advisory
            ids.append(alert.advisory.ghsa_id.lower())
            #  CWE support
            ids.extend(alert.advisory.cwes)

            names = [
                # org.apache.commons
                dependency.fullname,
                #  maven://org.apache.commons
                dependency.getPurl(version=False),
            ]

            if self.policy.checkViolation(
                severity,
                "dependabot",
                names=names,
                ids=ids,
                creation_time=alert_creation_time,
            ):
                dependabot_violations.append(
                    [
                        alert.advisory.ghsa_id,
                        "\n".join(alert.advisory.cwes),
                        alert.severity,
                        alert_creation_time.strftime("%Y-%m-%dT%XZ"),
                    ]
                )
                if self.display:
                    Octokit.error(
                        f"Dependabot Alert :: {alert.advisory.ghsa_id} ({alert.severity}) - {alert.purl}"
                    )

        violation_count = len(dependabot_violations)
        Octokit.info(f"Dependabot violations :: {violation_count}")

        Octokit.endGroup()

        if violation_count == 0:
            Summary.addLine(f"{Summary.__ICONS__['check']} 0 Dependabot violations")
        else:
            Summary.addLine(
                f"{Summary.__ICONS__['cross']} {violation_count} Dependabot violation{'s' if violation_count > 1 else ''}"
            )

        if self.display and violation_count > 0:
            Summary.addCollapsed(
                Summary.formatTable(
                    dependabot_violation_headers, dependabot_violations
                ),
                summary=Summary.formatItalics("Dependabot violations"),
            )

        return violation_count

    def checkDependencyLicensing(self):
        Octokit.createGroup(
            "Dependency Graph Results - Licensing",
            warning_prepfix="Dependency Graph Alert",
        )
        Summary.addHeader("Dependency Graph Results - Licensing", 2)
        licensing_headers = ["Dependency Name", "License"]
        licensing_warnings = []
        licensing_violations = []

        # Dependencies
        depgraph = DependencyGraph()
        if GitHub.repository.isInPullRequest():
            Octokit.info("Dependencies from Pull Request")
            pr_info = GitHub.repository.getPullRequestInfo()
            pr_base = pr_info.get("base", {}).get("ref", "")
            pr_head = pr_info.get("head", {}).get("ref", "")
            dependencies = depgraph.getDependenciesInPR(pr_base, pr_head)
        else:
            dependencies = depgraph.getDependencies()

        # license data
        licenses = Licenses()
        for license_path in LICENSES:
            licenses.load(license_path)

        Octokit.info(f"Loaded extra licensing information :: {len(licenses.data)}")

        dependencies.applyLicenses(licenses)

        Octokit.info("Total Dependencies in Graph :: " + str(len(dependencies)))

        if not self.policy.policy and not self.policy.policy.get("licensing"):
            Octokit.debug("Skipping as licensing policy not set")
            return len(licensing_violations)

        ignores_ids = (
            self.policy.policy.get("licensing", {}).get("ignores", {}).get("ids", [])
        )
        ignores_names = (
            self.policy.policy.get("licensing", {}).get("ignores", {}).get("names", [])
        )

        # Warnings (NA, etc)
        warnings = Dependencies()

        warnings_ids = (
            self.policy.policy.get("licensing", {}).get("warnings", {}).get("ids", [])
        )
        warnings_names = (
            self.policy.policy.get("licensing", {}).get("warnings", {}).get("names", [])
        )

        warnings.extend(dependencies.findLicenses(warnings_ids))
        warnings.extend(dependencies.findNames(warnings_names))

        for warning in warnings:
            if warning.name in ignores_names or warning.license in ignores_ids:
                Octokit.debug(f"Skipping {warning} because in ignore list...")
                continue

            licensing_warnings.append(
                [warning.fullname, warning.license if warning.license else "None"]
            )
            Octokit.warning(
                "Dependency License Warning :: {} = {}".format(
                    warning.fullname, warning.license
                )
            )

        # License Checks (GPL, etc)
        violations = Dependencies()

        violations_ids = (
            self.policy.policy.get("licensing", {}).get("conditions", {}).get("ids", [])
        )
        violations_names = (
            self.policy.policy.get("licensing", {})
            .get("conditions", {})
            .get("names", [])
        )

        violations.extend(dependencies.findLicenses(violations_ids))
        violations.extend(dependencies.findNames(violations_names))

        for violation in violations:
            if violation.name in ignores_names or violation.license in ignores_ids:
                Octokit.debug(f"Skipping {violation} because in ignore list...")
                continue

            licensing_violations.append(
                [violation.fullname, violation.license if warning.license else "None"]
            )
            if self.display:
                Octokit.error(
                    "Dependency Graph Alert :: {} = {}".format(
                        violation, violation.license
                    )
                )

        violation_count = len(licensing_violations)
        warning_count = len(licensing_warnings)
        Octokit.info(f"Dependency Graph violations :: {violation_count}")

        Octokit.endGroup()

        if violation_count == 0:
            Summary.addLine(
                f"{Summary.__ICONS__['check']} 0 Dependency License violations"
            )
        else:
            Summary.addLine(
                f"{Summary.__ICONS__['cross']} {violation_count} Dependency License violation{'s' if violation_count > 1 else ''}"
            )

        if self.display and violation_count > 0:
            Summary.addCollapsed(
                Summary.formatTable(licensing_headers, licensing_violations),
                summary=Summary.formatItalics("Dependency License violations"),
            )

        if warning_count == 0:
            Summary.addLine(
                f"{Summary.__ICONS__['check']} 0 Dependency License warnings"
            )
        else:
            Summary.addLine(
                f"{Summary.__ICONS__['warning']} {warning_count} Dependency License warning{'s' if warning_count > 1 else ''}"
            )

        if self.display and warning_count > 0:
            Summary.addCollapsed(
                Summary.formatTable(licensing_headers, licensing_warnings),
                summary=Summary.formatItalics("Dependency License warnings"),
            )

        return violation_count

    def checkDependencies(self):
        Octokit.createGroup(
            "Dependency Graph",
            warning_prepfix="Dependency Graph Alert",
        )
        Summary.addHeader("Dependency Graph Results", 2)
        dependency_violation_headers = ["Dependency Name"]
        dependency_violations = []

        # Dependencies
        depgraph = DependencyGraph()
        if GitHub.repository.isInPullRequest():
            Octokit.info("Dependencies from Pull Request")
            pr_info = GitHub.repository.getPullRequestInfo()
            pr_base = pr_info.get("base", {}).get("ref", "")
            pr_head = pr_info.get("head", {}).get("ref", "")
            dependencies = depgraph.getDependenciesInPR(pr_base, pr_head)

        else:
            dependencies = depgraph.getDependencies()

        Octokit.info("Total Dependency Graph :: " + str(len(dependencies)))

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
                dependency_violations.append([dependency.fullname])
                if self.display:
                    Octokit.error(
                        "Dependency Graph Alert :: {}".format(dependency.fullname)
                    )

        violation_count = len(dependency_violations)
        Octokit.info(f"Dependency Graph violations :: {violation_count}")

        Octokit.endGroup()

        if violation_count == 0:
            Summary.addLine(f"{Summary.__ICONS__['check']} 0 Dependency violations")
        else:
            Summary.addLine(
                f"{Summary.__ICONS__['cross']} {violation_count} Dependency violation{'s' if violation_count > 1 else ''}"
            )

        if self.display and violation_count > 0:
            Summary.addCollapsed(
                Summary.formatTable(
                    dependency_violation_headers, dependency_violations
                ),
                summary=Summary.formatItalics("Dependency violations"),
            )

        return violation_count

    def checkSecretScanning(self):
        # Secret Scanning Results
        Octokit.createGroup("Secret Scanning Results")
        Summary.addHeader("Secret Scanning Results", 2)
        secret_violation_headers = ["Secret Type", "Alert Creation Time"]
        secret_violations = []

        secretscanning = SecretScanning()
        if GitHub.repository.isInPullRequest():
            Octokit.info("Secret Scanning Alerts from Pull Request")
            alerts = secretscanning.getAlertsInPR()
        else:
            alerts = secretscanning.getAlerts("open")

        Octokit.info("Total Secret Scanning Alerts :: " + str(len(alerts)))

        for alert in alerts:
            alert_creation_time = datetime.strptime(
                alert.get("created_at"), "%Y-%m-%dT%XZ"
            )

            ids = []
            ids.append(alert.secret_type)

            if self.policy.checkViolation(
                "critical", "secretscanning", ids=ids, creation_time=alert_creation_time
            ):
                secret_violations.append(
                    [
                        alert.secret_type_display_name,
                        alert_creation_time.strftime("%Y-%m-%dT%XZ"),
                    ]
                )
                if self.display:
                    Octokit.error(f"Unresolved Secret - {alert}")

        violation_count = len(secret_violations)
        Octokit.info(f"Secret Scanning violations :: {violation_count}")

        Octokit.endGroup()

        if violation_count == 0:
            Summary.addLine(
                f"{Summary.__ICONS__['check']} 0 Secret Scanning violations"
            )
        else:
            Summary.addLine(
                f"{Summary.__ICONS__['cross']} {violation_count} Secret Scanning violation{'s' if violation_count > 1 else ''}"
            )

        if self.display and violation_count > 0:
            Summary.addCollapsed(
                Summary.formatTable(secret_violation_headers, secret_violations),
                summary=Summary.formatItalics("Secret Scanning violations"),
            )

        return violation_count

    def isRemediationPolicy(self, technology: str = "general") -> bool:
        return self.policy.policy.get(technology, {}).get("remediate") is not None
