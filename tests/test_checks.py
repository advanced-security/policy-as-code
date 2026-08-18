import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.append(".")

from ghastoolkit import GitHub
from ghastoolkit.octokit.graphql import QUERIES

from ghascompliance import checks as checks_module
from ghascompliance.checks import Checks
from ghascompliance.policy import Policy


class TestGraphQLQueries(unittest.TestCase):
    def testNoLocalQueryOverrides(self):
        """Local queries would override the paginated ghastoolkit queries."""
        path = os.path.join(
            os.path.dirname(checks_module.__file__), "octokit", "graphql"
        )
        self.assertFalse(os.path.exists(path))

    def testDependencyInfoQueryIsPaginated(self):
        """Un-paginated queries time out (502) on large repositories."""
        query = QUERIES.get("GetDependencyInfo", "")

        self.assertIn("dependencyGraphManifests(first:", query)
        self.assertIn("$manifests_cursor", query)
        self.assertIn("$dependencies_cursor", query)


class TestDependabotChecks(unittest.TestCase):
    def setUp(self) -> None:
        GitHub.init(
            "advanced-security/policy-as-code",
            reference="refs/heads/main",
            retrieve_metadata=False,
        )
        self.checks = Checks(Policy("error"))
        return super().setUp()

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
        alert = MagicMock()
        alert.get.return_value = None
        alert.purl = "pkg:npm/lodash"

        depgraph = MagicMock()
        depgraph.getDependencies.return_value.findPurl.return_value = None
        dependabot = MagicMock()
        dependabot.getAlerts.return_value = [alert]

        with patch.object(checks_module, "Dependabot", return_value=dependabot):
            with patch.object(checks_module, "DependencyGraph", return_value=depgraph):
                violations = self.checks.checkDependabot()

        self.assertEqual(violations, 0)
        depgraph.getDependencies.assert_called_once()
