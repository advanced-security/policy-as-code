import os
import sys
import yaml
import uuid
import unittest
import tempfile

sys.path.append(".")

from ghascompliance.octokit.octokit import GitHub


class TestPolicyLoading(unittest.TestCase):
    def testGitHubInstance(self):
        instance = "https://github.com"
        github = GitHub("GeekMasher/advanced-security-compliance", instance=instance)

        self.assertEqual(github.get("instance"), instance)
        self.assertEqual(github.get("api.rest"), "https://api.github.com")
        self.assertEqual(github.get("api.graphql"), "https://api.github.com/graphql")

    def testGitHubServerInstance(self):
        instance = "https://ghes.example.com"
        github = GitHub("GeekMasher/advanced-security-compliance", instance=instance)

        self.assertEqual(github.get("instance"), instance)
        self.assertEqual(github.get("api.rest"), "https://ghes.example.com/api/v3")
        self.assertEqual(
            github.get("api.graphql"), "https://ghes.example.com/api/graphql"
        )

    def testInPullRequest(self):
        # main ref
        github = GitHub("advanced-security/policy-as-code", ref="refs/heads/main")
        self.assertEqual(github.inPullRequest(), False)
        # pr ref
        github = GitHub("advanced-security/policy-as-code", ref="refs/pull/1/merge")
        self.assertEqual(github.inPullRequest(), True)

    def testGetPullRequestNumber(self):
        github = GitHub("advanced-security/policy-as-code", ref="refs/pull/1/merge")
        pr_id = github.getPullRequestNumber()
        self.assertTrue(isinstance(pr_id, int))
        self.assertEqual(pr_id, 1)

        # not a pull request
        github = GitHub("advanced-security/policy-as-code", ref="refs/heads/main")
        pr_id = github.getPullRequestNumber()
        self.assertTrue(isinstance(pr_id, int))
        # we default to 0
        self.assertEqual(pr_id, 0)
