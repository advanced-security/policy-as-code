"""ProjectBoard Plugin."""
import logging

from ghascompliance.plugins.plugin import Plugin

logger = logging.getLogger("ghascompliance.plugins.projectboard")


class ProjectBoardPlugin(Plugin):
    """ProjectBoardPlugin."""

    def post(self):
        logger.warning("Running ProjectBoard")
