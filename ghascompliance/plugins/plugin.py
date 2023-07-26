"""Plugins."""


class Plugin:
    """Plugin."""

    def __init__(self, name: str, **settings) -> None:
        """Initialise Plugin."""
        self.name = name
        self.settings = settings

    def pre(self):
        """Pre-Plugin."""
        return

    def post(self):
        """Post-Plugin."""
        return

    def run(self):
        """Run Plugin."""
        raise Exception(f"")


class Plugins:
    def __init__(self, **plugins: dict[str, Plugin]) -> None:
        self.plugins: dict[str, Plugin] = plugins

    def runPre(self):
        """Run Pre-Plugin."""
        for name, plugin in self.plugins.items():
            plugin.pre()

    def runPost(self):
        """Run Post-Plugin."""
        for name, plugin in self.plugins.items():
            plugin.post()
