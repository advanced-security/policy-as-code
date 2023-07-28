"""Plugins."""


class Plugin:
    """Plugin."""

    def __init__(self, name: str, **settings) -> None:
        """Initialise Plugin."""
        self.name = name
        self.settings = settings

    def pre(self, **kwargs):
        """Pre-Plugin."""
        return

    def post(self, **kwargs):
        """Post-Plugin."""
        return

    def run(self):
        """Run Plugin."""
        raise Exception(f"")


class Plugins:
    def __init__(self, **plugins: dict[str, Plugin]) -> None:
        self.plugins: dict[str, Plugin] = plugins

    def runPre(self, **kwargs):
        """Run Pre-Plugin."""
        for name, plugin in self.plugins.items():
            plugin.pre(**kwargs)

    def runPost(self, **kwargs):
        """Run Post-Plugin."""
        for name, plugin in self.plugins.items():
            plugin.post(**kwargs)

    def __len__(self) -> int:
        return len(self.plugins)
