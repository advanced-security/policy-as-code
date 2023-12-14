import os
import sys
import yaml
import uuid
import unittest
import tempfile

sys.path.append(".")

from ghascompliance.octokit.octokit import GitHub


class TestPolicyLoading(unittest.TestCase):
    def setUp(self) -> None:
        # reset
        GitHub.init("advanced-security/policy-as-code", instance="https://github.com")

    def testGitHubInstance(self):
        instance = "https://github.com"
        GitHub.init(
            "advanced-security/policy-as-code",
            instance=instance,
            retrieve_metadata=False,
        )

        self.assertEqual(GitHub.instance, instance)
        self.assertEqual(GitHub.api_rest, "https://api.github.com")
        self.assertEqual(GitHub.api_graphql, "https://api.github.com/graphql")

    def testGitHubServerInstance(self):
        instance = "https://ghes.example.com"
        GitHub.init(
            "advanced-security/policy-as-code",
            instance=instance,
            retrieve_metadata=False,
        )

        self.assertEqual(GitHub.instance, instance)
        self.assertEqual(GitHub.api_rest, "https://ghes.example.com/api/v3")
        self.assertEqual(GitHub.api_graphql, "https://ghes.example.com/api/graphql")

    def testInPullRequest(self):
        # main ref
        GitHub.init("advanced-security/policy-as-code", reference="refs/heads/main")
        self.assertEqual(GitHub.repository.isInPullRequest(), False)

        # pr ref
        GitHub.init("advanced-security/policy-as-code", reference="refs/pull/1/merge")
        self.assertEqual(GitHub.repository.isInPullRequest(), True)

    def testGetPullRequestNumber(self):
        GitHub.init("advanced-security/policy-as-code", reference="refs/pull/1/merge")
        pr_id = GitHub.repository.getPullRequestNumber()
        self.assertTrue(isinstance(pr_id, int))
        self.assertEqual(pr_id, 1)

        # not a pull request
        GitHub.init("advanced-security/policy-as-code", reference="refs/heads/main")
        self.assertFalse(GitHub.repository.isInPullRequest())
