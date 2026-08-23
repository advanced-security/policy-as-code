import os
import sys
import yaml
import uuid
import unittest
import tempfile
from unittest.mock import patch

sys.path.append(".")

from ghascompliance.octokit.octokit import GitHub
from ghascompliance.octokit.pullrequest import PullRequest
from ghascompliance.octokit.summary import Summary


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


class TestPullRequest(unittest.TestCase):
    def setUp(self) -> None:
        PullRequest.add_pr_comment = True
        Summary.summary = "Policy results\n"

    def tearDown(self) -> None:
        PullRequest.add_pr_comment = False
        Summary.summary = ""

    @patch.dict(
        os.environ,
        {
            "GITHUB_SERVER_URL": "https://github.example.com",
            "GITHUB_REPOSITORY": "advanced-security/policy-as-code",
            "GITHUB_RUN_ID": "123456",
        },
        clear=True,
    )
    @patch("ghascompliance.octokit.pullrequest.GitHub.repository")
    def testAddPrCommentIncludesWorkflowRunSummaryLink(self, repository_mock) -> None:
        repository_mock.isInPullRequest.return_value = True
        repository_mock.getPullRequestComments.return_value = []

        PullRequest.addPrComment("Test policy")

        comment = repository_mock.createPullRequestComment.call_args.args[0]
        self.assertIn(
            "[View workflow run summary]"
            "(https://github.example.com/advanced-security/policy-as-code/"
            "actions/runs/123456)",
            comment,
        )

    @patch.dict(
        os.environ,
        {
            "GITHUB_SERVER_URL": "https://github.example.com/",
            "GITHUB_REPOSITORY": "/advanced-security/policy-as-code",
            "GITHUB_RUN_ID": " 123456 ",
        },
        clear=True,
    )
    @patch("ghascompliance.octokit.pullrequest.GitHub.repository")
    def testAddPrCommentNormalisesWorkflowRunContext(self, repository_mock) -> None:
        repository_mock.isInPullRequest.return_value = True
        repository_mock.getPullRequestComments.return_value = []

        PullRequest.addPrComment("Test policy")

        comment = repository_mock.createPullRequestComment.call_args.args[0]
        self.assertIn(
            "[View workflow run summary]"
            "(https://github.example.com/advanced-security/policy-as-code/"
            "actions/runs/123456)",
            comment,
        )

    @patch.dict(
        os.environ,
        {
            "GITHUB_SERVER_URL": "https://github.example.com",
            "GITHUB_REPOSITORY": "advanced-security/policy-as-code",
            "GITHUB_RUN_ID": "123456",
        },
        clear=True,
    )
    @patch("ghascompliance.octokit.pullrequest.GitHub.repository")
    def testAddPrCommentIncludesWorkflowRunSummaryLinkOnUpdate(
        self, repository_mock
    ) -> None:
        comment_marker = PullRequest.__COMMENT_MARKER__.format(id="Test policy")
        repository_mock.isInPullRequest.return_value = True
        repository_mock.getPullRequestComments.return_value = [
            {"id": 1, "body": f"Policy results\n{comment_marker}"}
        ]

        PullRequest.addPrComment("Test policy")

        comment = repository_mock.updatePullRequestComment.call_args.args[1]
        self.assertIn(
            "[View workflow run summary]"
            "(https://github.example.com/advanced-security/policy-as-code/"
            "actions/runs/123456)",
            comment,
        )

    @patch.dict(os.environ, {"GITHUB_RUN_ID": "123456"}, clear=True)
    @patch("ghascompliance.octokit.pullrequest.GitHub.repository")
    def testAddPrCommentOmitsLinkWithoutWorkflowRunContext(
        self, repository_mock
    ) -> None:
        repository_mock.isInPullRequest.return_value = True
        repository_mock.getPullRequestComments.return_value = []

        PullRequest.addPrComment("Test policy")

        comment = repository_mock.createPullRequestComment.call_args.args[0]
        self.assertNotIn("workflow run summary", comment)
