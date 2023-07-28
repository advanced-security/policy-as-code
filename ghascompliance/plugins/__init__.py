from ghascompliance.plugins.prcommenting import PullRequestCommenting
from ghascompliance.plugins.projectboard import ProjectBoardPlugin

__PLUGINS__ = {
    "projectboard": ProjectBoardPlugin,
    "pr-commenting": PullRequestCommenting,
}
