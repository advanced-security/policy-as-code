"""Policy Engine."""
import os
import json
import shutil
import tempfile
from typing import Optional

from ghastoolkit import GitHub, Repository
from ghascompliance.checks.codescanning import CodeScanningChecker

from ghascompliance import Octokit
from ghascompliance.plugins import __PLUGINS__
from ghascompliance.plugins.plugin import Plugins
from ghascompliance.policies.base import PolicyConfig, PolicyV3


__ROOT__ = os.path.dirname(os.path.basename(__file__))


class PolicyEngine:
    """Policy Engine."""

    def __init__(
        self,
        repository: Optional[Repository] = None,
        path: Optional[str] = None,
    ):
        """Initialise Policy as Engine."""
        self.repository = repository
        self.repository_path = path

        if self.repository:
            self.root_policy = self.loadFromRepo()
        elif path:
            self.root_policy = self.loadLocalConfig(path)
        else:
            raise Exception("Failed to load policy (no path or repository)")

        self.policy = self.root_policy.getPolicy(GitHub.repository)
        Octokit.debug(f"Loaded Policy :: {self.policy.name}")

        self.checkers = [CodeScanningChecker("Code Scanning", self.policy)]
        Octokit.debug(f"Loaded Checkers :: {len(self.checkers)}")

        Octokit.debug("Loading plugins...")
        self.plugins = Plugins()

        for plugin_name, plugin in __PLUGINS__.items():
            if self.root_policy.plugins.get(plugin_name):
                Octokit.debug(f"Loading plugin :: `{plugin_name}`")
                settings = self.root_policy.plugins.get(plugin_name, {})

                self.plugins.plugins[plugin_name] = plugin(plugin_name, **settings)

        Octokit.debug(f"Loaded Plugins :: {len(self.plugins)}")

        self.temp_repo = None

    def loadFromRepo(self):
        """Load policy from repository."""
        if not self.repository:
            raise Exception(f"Loading from repository but no repository is set")

        # setup
        self.repository.clone_path = os.path.join(tempfile.gettempdir(), "repo")
        Octokit.debug(f"Clone Policy URL :: {self.repository.clone_url}")

        if os.path.exists(self.repository.clone_path):
            Octokit.debug("Deleting existing temp path")
            shutil.rmtree(self.repository.clone_path)

        Octokit.info(f"Cloning policy repo - {self.repository}")
        Octokit.debug(f"Is GitHub Token present - {GitHub.token is not None}")

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

    def check(self) -> int:
        """Run all the checks."""
        total = 0

        for checker in self.checkers:
            Octokit.createGroup(f"{checker.name} Results")
            checker.check()

            for critical in checker.state.criticals:
                Octokit.error(critical.get("msg"))

            for warning in checker.state.warnings:
                if self.root_policy.display:
                    Octokit.warning(warning.get("msg"))

            for err in checker.state.errors:
                if self.root_policy.display:
                    Octokit.error(err.get("msg"))

            Octokit.info(f"{checker.name} warnings   :: {len(checker.state.warnings)}")
            Octokit.info(f"{checker.name} violations :: {len(checker.state.errors)}")

            total += len(checker.state.criticals)
            total += len(checker.state.errors)

            Octokit.endGroup()

        return total

    def savePolicy(self, path: str):
        #  Always clear the file
        Octokit.info("Saving Policy...")
        if os.path.exists(path):
            os.remove(path)
        with open(path, "w") as handle:
            json.dump(self.policy, handle, indent=2)
        Octokit.info("Policy saved")
