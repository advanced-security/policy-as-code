import datetime
from typing import Union

from ghastoolkit import GitHub

from ghascompliance.octokit.octokit import Octokit
from ghascompliance.octokit.summary import Summary


class PullRequest:
    __COMMENT_MARKER__: str = "<!-- policy-as-code-pr-comment-marker :: {id} -->"

    add_pr_comment: bool = False

    @staticmethod
    def addPrComment(policy_name: str) -> None:
        """Adds the given summary as a comment on the Pull Request.
        Does nothing if the action isn't running in a PR."""
        if not PullRequest.add_pr_comment:
            Octokit.debug("PR comments are not enabled, skipping.")
            return
        if not GitHub.repository.isInPullRequest():
            Octokit.debug("Not running in a PR, skipping PR comment.")
            return

        Octokit.createGroup("Pull Request comment")

        policy_name = policy_name if policy_name else "Unknown"
        comment_marker = PullRequest.__COMMENT_MARKER__.format(id=policy_name)
        Summary.addRaw(comment_marker)

        try:
            # Check if there's an existing comment with the commit marker string
            comment_id = PullRequest.findComment(comment_marker)

            # If existing comment, update the comment
            if comment_id:
                Octokit.info(
                    "Found an existing comment from PaC, updating that comment..."
                )
                Octokit.debug(f"Comment ID :: {comment_id}")
                Summary.addRaw(f"Updating the comment at {datetime.datetime.today()}")
                GitHub.repository.updatePullRequestComment(comment_id, Summary.summary)
            # Else, add a new comment
            else:
                Octokit.info("No exisiting comment from PaC, adding a new comment...")
                GitHub.repository.createPullRequestComment(Summary.summary)
        except Exception as ex:
            Octokit.error(
                "Exception occured when attempting to add a PR comment, ensure that the auth token has write access to Pull Requests."
            )
        finally:
            Octokit.endGroup()

    @staticmethod
    def findComment(comment_body_includes: str) -> Union[int, None]:
        """Finds a comment in the PR containing the given string."""
        comments = GitHub.repository.getPullRequestComments()
        Octokit.debug(f"Found {len(comments)} comments in this PR.")
        for comment in comments:
            if comment_body_includes in comment.get("body", ""):
                return comment.get("id", None)
        return None
