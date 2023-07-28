"""Pull Request Commenting Plugin."""
from ghascompliance.octokit.octokit import Octokit
from ghascompliance.plugins.plugin import Plugin


class PullRequestCommenting(Plugin):
    """Pull Request Commenting."""

    def post(self, **kwargs):
        """Once completed policy checking, comment in the PR."""
        Octokit.info("PR Commening...")
