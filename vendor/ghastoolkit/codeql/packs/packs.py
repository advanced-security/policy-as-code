"""CodeQL Packs."""

import os
import logging
from typing import List, Optional

from ghastoolkit.codeql.packs.pack import CodeQLPack


logger = logging.getLogger("ghastoolkit.codeql.packs")


class CodeQLPacks:
    """CodeQL List of Packs."""

    def __init__(self, path: Optional[str] = None) -> None:
        """Initialise CodeQLPacks."""
        self.packs: List[CodeQLPack] = []

        if path:
            self.load(os.path.realpath(os.path.expanduser(path)))

    def append(self, pack: CodeQLPack):
        """Append a CodeQLPack."""
        self.packs.append(pack)

    def load(self, path: str):
        """Load packs from path."""
        if not os.path.exists(path):
            raise Exception("Path does not exist")

        logger.debug(f"Loading from path :: {path}")
        lib_path = os.path.join(".codeql", "libraries")

        for root, _, files in os.walk(path):
            for file in files:
                if file == "qlpack.yml":
                    fpath = os.path.join(root, file)

                    if lib_path in fpath:
                        continue
                    self.append(CodeQLPack(fpath))

    def __iter__(self):
        return self.packs.__iter__()

    def __len__(self) -> int:
        """Get length / amount of loaded packs."""
        return len(self.packs)

    def __str__(self) -> str:
        """To String."""
        return f"CodeQLPacks('{len(self)}')"
