"""Checker."""
import datetime
import fnmatch
from typing import List
from ghascompliance.policies.base import Policy

from ghascompliance.policies.state import PolicyState


class Checker:
    """Checker Class."""

    def __init__(self, name: str, policy: Policy) -> None:
        self.name = name
        self.policy = policy

        self.state = PolicyState(name)
        self.severities = []

    def check(self) -> PolicyState:
        raise Exception(f"Child checker does not support check function")

    def matchContent(self, name: str, validators: List[str]):
        """Wildcard matching helper"""
        for validator in validators:
            results = fnmatch.filter([name], validator)
            if results:
                return True
        return False

    def checkViolationRemediation(
        self,
        severity: str,
        remediate: dict,
        creation_time: datetime.datetime,
    ):
        # Midnight "today"
        now = datetime.datetime.now().date()

        if creation_time and remediate.get(severity):
            alert_datetime = creation_time + datetime.timedelta(
                days=int(remediate.get(severity))
            )
            if now > alert_datetime.date():
                return True

        else:
            for remediate_severity, remediate_delta in remediate.items():
                remediate_severity_list = self._buildSeverityList(remediate_severity)

                if severity in remediate_severity_list:
                    alert_datetime = creation_time + datetime.timedelta(
                        days=int(remediate_delta)
                    )
                    if now > alert_datetime.date():
                        return True

        return False

    def checkViolation(
        self,
        severity: str,
        technology: str,
        names: List[str] = [],
        ids: List[str] = [],
        creation_time: datetime.datetime = None,
    ):
        severity = severity.lower()

        if not technology or technology == "":
            raise Exception("Technology is set to None")

        if self.policy.get(technology, {}).get("remediate"):
            Octokit.debug("Checking violation against remediate configuration")

            remediate_policy = self.policy.get(technology, {}).get("remediate")

            violation_remediation = self.checkViolationRemediation(
                severity, remediate_policy, creation_time
            )
            if self.policy.get(technology, {}).get("level"):
                return violation_remediation and self.checkViolationAgainstPolicy(
                    severity, technology, names=names, ids=ids
                )
            else:
                return violation_remediation

        elif self.policy:
            return self.checkViolationAgainstPolicy(
                severity, technology, names=names, ids=ids
            )
        else:
            if severity == "none":
                return False
            elif severity == "all":
                return True
            elif severity not in SEVERITIES:
                Octokit.warning(f"Unknown Severity used - {severity}")

            return severity in self.severities

    def checkViolationAgainstPolicy(
        self, severity: str, technology: str, names: List[str] = [], ids: List[str] = []
    ):
        severities = []
        level = "all"

        if technology:
            policy = self.policy.get(technology)
            if policy:
                for name in names:
                    check_name = str(name).lower()
                    condition_names = [
                        ign.lower()
                        for ign in policy.get("conditions", {}).get("names", [])
                    ]
                    ingores_names = [
                        ign.lower()
                        for ign in policy.get("ignores", {}).get("names", [])
                    ]
                    if self.matchContent(check_name, ingores_names):
                        return False
                    elif self.matchContent(check_name, condition_names):
                        return True

                for id in ids:
                    check_id = str(id).lower()
                    condition_ids = [
                        ign.lower()
                        for ign in policy.get("conditions", {}).get("ids", [])
                    ]
                    ingores_ids = [
                        ign.lower() for ign in policy.get("ignores", {}).get("ids", [])
                    ]
                    if self.matchContent(check_id, ingores_ids):
                        return False
                    elif self.matchContent(check_id, condition_ids):
                        return True

            if self.policy.get(technology, {}).get("level"):
                level = self.policy.get(technology, {}).get("level")
                severities = self._buildSeverityList(level)
        else:
            severities = self.severities

        if level == "all":
            severities = SEVERITIES
        elif level == "none":
            severities = []

        return severity in severities

    def checkLicensingViolation(self, license: str, dependency: dict = {}):
        license = license.lower()

        # Policy as Code
        if self.policy and self.policy.get("licensing"):
            return self.checkLicensingViolationAgainstPolicy(license, dependency)

        return license in [l.lower() for l in LICENSES]

    def checkLicensingViolationAgainstPolicy(self, license: str, dependency: dict = {}):
        policy = self.policy.get("licensing")
        license = license.lower()

        dependency_short_name = dependency.get("name", "NA")
        dependency_name = (
            dependency.get("manager", "NA") + "://" + dependency.get("name", "NA")
        )
        dependency_full = dependency.get("full_name", "NA://NA#NA")

        # gather warning ids and names
        warning_ids = [wrn.lower() for wrn in policy.get("warnings", {}).get("ids", [])]
        warning_names = [
            wrn.lower() for wrn in policy.get("warnings", {}).get("names", [])
        ]

        #  if the license name is in the warnings list generate a warning
        if self.matchContent(license, warning_ids) or self.matchContent(
            dependency_full, warning_names
        ):
            Octokit.warning(
                f"Dependency License Warning :: {dependency_full} = {license}"
            )

        # gather ignore ids and names
        ingore_ids = [ign.lower() for ign in policy.get("ingores", {}).get("ids", [])]
        ingore_names = [
            ign.lower() for ign in policy.get("ingores", {}).get("names", [])
        ]

        # gather condition ids and names
        condition_ids = [
            ign.lower() for ign in policy.get("conditions", {}).get("ids", [])
        ]
        conditions_names = [
            ign.lower() for ign in policy.get("conditions", {}).get("names", [])
        ]

        for value in [license, dependency_full, dependency_name, dependency_short_name]:
            # return false (ignore) if name or id is defined in the ignore portion of the policy
            if self.matchContent(value, ingore_ids) or self.matchContent(
                value, ingore_names
            ):
                return False
            # annotate error and return true if name or id is defined as a condition
            elif self.matchContent(value, condition_ids) or self.matchContent(
                value, conditions_names
            ):
                Octokit.error(
                    f"Dependency License Violation :: {dependency_full} == {license}"
                )
                return True

        return False
