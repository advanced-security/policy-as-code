import os
import json
import yaml
import shutil
import fnmatch
import datetime
import tempfile
from typing import List, Dict, Optional

from ghastoolkit import Repository

from ghascompliance.consts import SEVERITIES, TECHNOLOGIES, LICENSES
from ghascompliance.octokit import Octokit

__ROOT__ = os.path.dirname(os.path.basename(__file__))
__SCHEMA_VALIDATION__ = "Schema Validation Failed :: {msg} - {value}"


class Policy:
    __BLOCK_ITEMS__ = ["ids", "names", "imports", "remediate"]
    __SECTION_ITEMS__ = ["level", "remediate", "conditions", "warnings", "ignores"]
    __IMPORT_ALLOWED_TYPES__ = ["txt"]

    def __init__(
        self,
        severity: str = "error",
        repository: Optional[str] = None,
        token: Optional[str] = None,
        isGithubAppToken: bool = False,
        path: Optional[str] = None,
        branch: Optional[str] = None,
        instance: str = "https://github.com",
    ):
        self.name = ""
        self.risk_level = severity

        self.severities = self._buildSeverityList(severity)

        self.policy = {}
        self.remediate = None

        self.instance = instance
        self.token = token
        self.isGithubAppToken = isGithubAppToken

        if repository:
            self.repository = Repository.parseRepository(repository)
            self.repository.branch = branch
            self.repository.repo_token = self.token
            self.repository.is_github_app_token = self.isGithubAppToken
        else:
            self.repository = None

        self.repository_path = path

        self.temp_repo = None

        if repository and repository != "":
            self.loadFromRepo()
        elif path and path != "":
            self.loadLocalConfig(path)

    def loadFromRepo(self):
        """Load policy from repository"""
        if not self.repository:
            raise Exception(f"Loading from repository but no repository is set")

        # setup
        self.repository.clone_path = os.path.join(tempfile.gettempdir(), "repo")
        self.temp_repo = self.repository.clone_path
        Octokit.debug(f"Clone Policy URL :: {self.repository.clone_url}")

        if os.path.exists(self.repository.clone_path):
            Octokit.debug("Deleting existing temp path")
            shutil.rmtree(self.repository.clone_path)

        Octokit.info(f"Cloning policy repo - {self.repository}")
        self.repository.clone(clobber=True, depth=1)

        if (
            not os.path.exists(self.repository.clone_path)
            and not self.repository.is_github_app_token
        ):
            # Try as a GitHub App Token
            Octokit.info("Retrying as GitHub App Token")

            self.repository.is_github_app_token = True
            self.repository.clone(clobber=True, depth=1)

        if not os.path.exists(self.repository.clone_path):
            raise Exception("Repository failed to clone")

        # get the policy file
        full_path = self.repository.getFile(self.repository_path or "policy.yml")

        self.loadLocalConfig(full_path)

    def loadLocalConfig(self, path: str):
        Octokit.info(f"Loading policy file - {path}")

        if not os.path.exists(path):
            raise Exception(f"Policy File does not exist - {path}")

        with open(path, "r") as handle:
            policy = yaml.safe_load(handle)

        self.loadPolicy(policy)

    def loadPolicy(self, policy: dict):
        self.name = policy.get("name", "")

        if not policy.get("general"):
            policy["general"] = {}

        general = policy.get("general")

        # set 'general' to the current minimum
        if not general.get("level"):
            policy["general"]["level"] = self.risk_level.lower()

        if general.get("remediate"):
            self.remediate = general.get("remediate")
            policy["general"]["remediate"] = self.remediate

        for tech in TECHNOLOGIES:
            # Importing files
            policy[tech] = self.loadPolicySection(
                tech, policy.get(tech, policy["general"])
            )

        Octokit.info("Policy loaded successfully")

        self.policy = policy

    def loadPolicySection(self, name: str, data: Optional[Dict] = None):
        time_to_remediate_policy = False

        if not data:
            data = {"level": "disabled"}

        for section, section_data in data.items():
            # check if only certain sections are present
            if section not in Policy.__SECTION_ITEMS__:
                raise Exception(
                    __SCHEMA_VALIDATION__.format(
                        msg="Disallowed Section present", value=section
                    )
                )

            # Skip level
            if section == "level" and isinstance(section_data, str):
                continue

            # Time to Remediate
            if section == "remediate":
                Octokit.debug("Enabling Time to Remediate (section) :: " + name)
                time_to_remediate_policy = True
                continue

            # Validate blocks
            for block in list(section_data):
                if block not in Policy.__BLOCK_ITEMS__:
                    raise Exception(
                        __SCHEMA_VALIDATION__.format(
                            msg="Disallowed Block present", value=block
                        )
                    )

            # Importing
            if section_data.get("imports"):
                if section_data.get("imports", {}).get("imports"):
                    raise Exception(
                        __SCHEMA_VALIDATION__.format(
                            msg="Circular import", value="imports"
                        )
                    )

                for block in Policy.__BLOCK_ITEMS__:
                    Octokit.debug(f"Importing > {section} - {block}")

                    import_path = section_data.get("imports", {}).get(block)
                    if import_path and isinstance(import_path, str):
                        if section_data.get(block):
                            section_data[block].extend(
                                self.loadPolicyImport(import_path)
                            )
                        else:
                            section_data[block] = self.loadPolicyImport(import_path)

        if not time_to_remediate_policy and self.remediate:
            Octokit.info("Enabling Time to Remediate (global) :: " + name)
            data["remediate"] = self.remediate

        return data

    def loadPolicyImport(self, path: str):
        results = []
        traversal = False
        paths = [
            # Current Working Dir
            (os.getcwd(), path),
            # Temp Repo / Cloned Repo
            (str(self.temp_repo), path),
            # Action / CLI directory
            (__ROOT__, path),
        ]
        for root, path in paths:
            full_path = os.path.abspath(os.path.join(root, path))

            if os.path.exists(full_path) and os.path.isfile(full_path):
                if full_path.startswith(tempfile.gettempdir()):
                    Octokit.debug("Temp location used for import path")
                elif not full_path.startswith(root):
                    Octokit.error("Attempting to import file :: " + full_path)
                    raise Exception("Path Traversal Detected, halting import!")

                # TODO: MIME type checking?
                _, fileext = os.path.splitext(full_path)
                fileext = fileext.replace(".", "")

                if fileext not in Policy.__IMPORT_ALLOWED_TYPES__:
                    Octokit.warning(
                        "Trying to load a disallowed file type :: " + fileext
                    )
                    continue

                Octokit.info("Importing Path :: " + full_path)

                with open(full_path, "r") as handle:
                    for line in handle:
                        line = line.replace("\n", "").replace("\b", "")
                        if line == "" or line.startswith("#"):
                            continue
                        results.append(line)

                return results
        Octokit.warning(f"Unable to import file :: {path}")
        return results

    def savePolicy(self, path: str):
        #  Always clear the file
        Octokit.info("Saving Policy...")
        if os.path.exists(path):
            os.remove(path)
        with open(path, "w") as handle:
            json.dump(self.policy, handle, indent=2)
        Octokit.info("Policy saved")

    def _buildSeverityList(self, severity: str):
        if not severity:
            raise Exception("`security` is set to None/Null")

        severity = severity.lower()
        severities = []

        if severity == "none":
            Octokit.debug("No Unacceptable Severities")
            return []
        elif severity == "all":
            Octokit.debug("Unacceptable Severities :: " + ",".join(SEVERITIES))
            return SEVERITIES
        elif severity in SEVERITIES:
            severities = SEVERITIES[: SEVERITIES.index(severity) + 1]
            Octokit.debug("Unacceptable Severities :: " + ",".join(severities))
        else:
            Octokit.warning(f"Unknown severity provided :: {severity}")
        return severities

    def matchContent(self, name: str, validators: List[str]):
        # Wildcard matching
        for validator in validators:
            results = fnmatch.filter([name], validator)
            if results:
                return True
        return False

    def checkTechnologyActive(self, technology: str):
        return self.policy.get(technology, {}).get("level", "") != "disabled"

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
