import sys
import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.append(".")

from ghastoolkit.errors import GHASToolkitError
from ghascompliance.checks import Checks


class TestChecks(unittest.TestCase):
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
    def test_check_dependabot_alert_without_dependency_graph_match_uses_purl(
        self, dependabot_cls, depgraph_cls, repository_mock
    ):
        repository_mock.isInPullRequest.return_value = False

        alert = self._create_alert()
        dependabot = dependabot_cls.return_value
        dependabot.graphql = MagicMock()
        dependabot.getAlerts.return_value = [alert]

        dependencies = MagicMock()
        dependencies.findPurl.return_value = None
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


if __name__ == "__main__":
    unittest.main()
