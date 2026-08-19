import os
import sys
import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.append(".")

from ghastoolkit import Dependencies, GitHub
from ghastoolkit.errors import GHASToolkitError
from ghastoolkit.octokit.graphql import QUERIES
from ghastoolkit.supplychain.dependency import Dependency

from ghascompliance import checks as checks_module
from ghascompliance.checks import Checks
from ghascompliance.policy import Policy


class TestGraphQLQueries(unittest.TestCase):
    def testNoLocalQueryOverrides(self):
        """Local queries would override the paginated ghastoolkit queries."""
        path = os.path.join(
            os.path.dirname(checks_module.__file__), "octokit", "graphql"
        )
        query_files = []
        if os.path.exists(path):
            query_files = [
                name for name in os.listdir(path) if name.endswith(".graphql")
            ]
        self.assertEqual(query_files, [])

    def testDependencyInfoQueryIsPaginated(self):
        """Un-paginated queries time out (502) on large repositories."""
        query = QUERIES.get("GetDependencyInfo", "")

        self.assertIn("dependencyGraphManifests(first:", query)
        self.assertIn("$manifests_cursor", query)
        self.assertIn("$dependencies_cursor", query)


class TestDependabotChecks(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        GitHub.init(
            "advanced-security/policy-as-code",
            reference="refs/heads/main",
            retrieve_metadata=False,
        )
        self.checks = Checks(Policy("error"))

    def _create_alert(self):
        advisory = SimpleNamespace(ghsa_id="GHSA-test-1234", cwes=["CWE-79"])
        alert = MagicMock()
        alert.purl = "pkg:pip/flask"
        alert.severity = "critical"
        alert.advisory = advisory
        alert.createdAt.return_value = datetime(2026, 8, 18, 0, 0, 0)
        alert.get.side_effect = lambda key, default=None: {"dismissReason": None}.get(
            key, default
        )
        return alert

    def testSkipDependencyGraphWithoutAlerts(self):
        depgraph = MagicMock()
        dependabot = MagicMock()
        dependabot.getAlerts.return_value = []

        with patch.object(checks_module, "Dependabot", return_value=dependabot):
            with patch.object(checks_module, "DependencyGraph", return_value=depgraph):
                violations = self.checks.checkDependabot()

        self.assertEqual(violations, 0)
        depgraph.getDependencies.assert_not_called()

    def testFetchDependencyGraphWithAlerts(self):
        alert = self._create_alert()

        depgraph = MagicMock()
        depgraph.getDependencies.return_value = Dependencies()
        dependabot = MagicMock()
        dependabot.getAlerts.return_value = [alert]

        with patch.object(checks_module, "Dependabot", return_value=dependabot):
            with patch.object(checks_module, "DependencyGraph", return_value=depgraph):
                violations = self.checks.checkDependabot()

        self.assertEqual(violations, 1)
        depgraph.getDependencies.assert_called_once()

    @patch("ghascompliance.checks.GitHub.repository")
    @patch("ghascompliance.checks.DependencyGraph")
    @patch("ghascompliance.checks.Dependabot")
    @patch("ghascompliance.checks.Octokit.warning")
    def test_check_dependabot_dependency_graph_400_still_processes_alerts(
        self, warning_mock, dependabot_cls, depgraph_cls, repository_mock
    ):
        repository_mock.isInPullRequest.return_value = False

        alert = self._create_alert()
        dependabot = dependabot_cls.return_value
        dependabot.graphql = MagicMock()
        dependabot.getAlerts.return_value = [alert]

        depgraph = depgraph_cls.return_value
        depgraph.getDependencies.side_effect = GHASToolkitError(
            "Bad Request", status=400
        )

        policy = MagicMock()
        policy.checkViolation.return_value = True

        checks = Checks(policy)
        self.assertEqual(checks.checkDependabot(), 1)
        policy.checkViolation.assert_called_once()
        self.assertFalse(
            any(
                "Unable to find alert in DependencyGraph" in call.args[0]
                for call in warning_mock.call_args_list
            )
        )

    @patch("ghascompliance.checks.GitHub.repository")
    @patch("ghascompliance.checks.DependencyGraph")
    @patch("ghascompliance.checks.Dependabot")
    @patch("ghascompliance.checks.Octokit.warning")
    def test_check_dependabot_alert_without_dependency_graph_match_uses_purl(
        self, warning_mock, dependabot_cls, depgraph_cls, repository_mock
    ):
        repository_mock.isInPullRequest.return_value = False

        alert = self._create_alert()
        dependabot = dependabot_cls.return_value
        dependabot.graphql = MagicMock()
        dependabot.getAlerts.return_value = [alert]

        alert.purl = "pkg:pip/flask@3.0.0"
        dependencies = Dependencies([Dependency(name="requests", manager="pip")])
        depgraph = depgraph_cls.return_value
        depgraph.getDependencies.return_value = dependencies

        policy = MagicMock()
        policy.checkViolation.return_value = True

        checks = Checks(policy)
        self.assertEqual(checks.checkDependabot(), 1)
        self.assertEqual(
            policy.checkViolation.call_args.kwargs["names"],
            [alert.purl, alert.purl],
        )
        warning_mock.assert_called_once_with(
            f"Unable to find alert in DependencyGraph :: {alert.purl}. Continuing with alert package URL"
        )

    @patch("ghascompliance.checks.GitHub.repository")
    @patch("ghascompliance.checks.DependencyGraph")
    @patch("ghascompliance.checks.Dependabot")
    @patch("ghascompliance.checks.Octokit.warning")
    def test_check_dependabot_purl_match_is_case_insensitive(
        self, warning_mock, dependabot_cls, depgraph_cls, repository_mock
    ):
        repository_mock.isInPullRequest.return_value = False

        alert = self._create_alert()
        alert.purl = "pkg:nuget/newtonsoft.json@13.0.3"
        dependabot = dependabot_cls.return_value
        dependabot.graphql = MagicMock()
        dependabot.getAlerts.return_value = [alert]

        dependency = Dependency(name="Newtonsoft.Json", manager="nuget")
        dependencies = Dependencies([dependency])
        depgraph = depgraph_cls.return_value
        depgraph.getDependencies.return_value = dependencies

        policy = MagicMock()
        policy.checkViolation.return_value = True

        checks = Checks(policy)
        self.assertEqual(checks.checkDependabot(), 1)
        self.assertEqual(
            policy.checkViolation.call_args.kwargs["names"],
            [dependency.fullname, dependency.getPurl(version=False)],
        )
        warning_mock.assert_not_called()

    @patch("ghascompliance.checks.GitHub.repository")
    @patch("ghascompliance.checks.DependencyGraph")
    @patch("ghascompliance.checks.Dependabot")
    @patch("ghascompliance.checks.Octokit.warning")
    def test_check_dependabot_maven_alert_matches_dependency_fullname(
        self, warning_mock, dependabot_cls, depgraph_cls, repository_mock
    ):
        repository_mock.isInPullRequest.return_value = False

        alert = self._create_alert()
        alert.purl = "pkg:maven/org.apache.commons:commons-lang3@3.14.0"
        dependabot = dependabot_cls.return_value
        dependabot.graphql = MagicMock()
        dependabot.getAlerts.return_value = [alert]

        dependency = Dependency(
            name="commons-lang3",
            namespace="org.apache.commons",
            manager="maven",
        )
        dependencies = Dependencies([dependency])
        depgraph = depgraph_cls.return_value
        depgraph.getDependencies.return_value = dependencies

        policy = MagicMock()
        policy.checkViolation.return_value = True

        checks = Checks(policy)
        self.assertEqual(checks.checkDependabot(), 1)
        self.assertEqual(
            policy.checkViolation.call_args.kwargs["names"],
            [dependency.fullname, dependency.getPurl(version=False)],
        )
        warning_mock.assert_not_called()

    @patch("ghascompliance.checks.GitHub.repository")
    @patch("ghascompliance.checks.DependencyGraph")
    @patch("ghascompliance.checks.Dependabot")
    @patch("ghascompliance.checks.Octokit.warning")
    def test_check_dependabot_scoped_npm_alert_matches_dependency_fullname(
        self, warning_mock, dependabot_cls, depgraph_cls, repository_mock
    ):
        repository_mock.isInPullRequest.return_value = False

        alert = self._create_alert()
        alert.purl = "pkg:npm/@scope/name@1.2.3"
        dependabot = dependabot_cls.return_value
        dependabot.graphql = MagicMock()
        dependabot.getAlerts.return_value = [alert]

        dependency = Dependency(name="name", namespace="@scope", manager="npm")
        dependencies = Dependencies([dependency])
        depgraph = depgraph_cls.return_value
        depgraph.getDependencies.return_value = dependencies

        policy = MagicMock()
        policy.checkViolation.return_value = True

        checks = Checks(policy)
        self.assertEqual(checks.checkDependabot(), 1)
        self.assertEqual(
            policy.checkViolation.call_args.kwargs["names"],
            [dependency.fullname, dependency.getPurl(version=False)],
        )
        warning_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
