import os
import json
import yaml
import shutil
import fnmatch
import datetime
import tempfile
from typing import List, Optional

from ghastoolkit.octokit.octokit import GitHub, Repository

from ghascompliance.consts import SEVERITIES, LICENSES
from ghascompliance.octokit import Octokit
from ghascompliance.policies.base import Policy, PolicyConfig, PolicyV3

__ROOT__ = os.path.dirname(os.path.basename(__file__))
__SCHEMA_VALIDATION__ = "Schema Validation Failed :: {msg} - {value}"


class PolicyEngine:
    def __init__(
        self,
        repository: Optional[Repository] = None,
        path: Optional[str] = None,
    ):
        self.repository = repository
        self.repository_path = path

        if self.repository:
            self.policy = self.loadFromRepo()
        elif path:
            self.policy = self.loadLocalConfig(path)
        else:
            raise Exception("Failed to load policy (no path or repository)")

        self.temp_repo = None

    def loadFromRepo(self):
        """Load policy from repository"""
        if not self.repository:
            raise Exception(f"Loading from repository but no repository is set")

        # setup
        self.repository.clone_path = os.path.join(tempfile.gettempdir(), "repo")
        Octokit.debug(f"Clone Policy URL :: {self.repository.clone_url}")

        if os.path.exists(self.repository.clone_path):
            Octokit.debug("Deleting existing temp path")
            shutil.rmtree(self.repository.clone_path)

        Octokit.info(f"Cloning policy repo - {self.repository}")
        self.repository.clone(clobber=True, depth=1)

        if not os.path.exists(self.repository.clone_path):
            raise Exception("Repository failed to clone")

        # get the policy file
        full_path = self.repository.getFile(self.repository_path or "policy.yml")

        return self.loadLocalConfig(full_path)

    def loadLocalConfig(self, path: str):
        Octokit.info(f"Loading policy file - {path}")

        if not os.path.exists(path):
            raise Exception(f"Policy File does not exist - {path}")
            
        PolicyConfig.base = os.path.realpath(os.path.dirname(path))
        return PolicyV3.loadRootPolicy(path)

    @property
    def codescanning_enabled(self) -> bool:
        if isinstance(self.policy.codescanning, (list)):
            return True  # assume that as list is enabled
        else:
            return self.policy.codescanning.enabled

    def savePolicy(self, path: str):
        #  Always clear the file
        Octokit.info("Saving Policy...")
        if os.path.exists(path):
            os.remove(path)
        with open(path, "w") as handle:
            json.dump(self.policy, handle, indent=2)
        Octokit.info("Policy saved")

    def matchContent(self, name: str, validators: List[str]):
        # Wildcard matching
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
