import os
import logging
from typing import List, Optional, Union
from dataclasses import dataclass, field

import yaml

from ghastoolkit.codeql.dataextensions.models import (
    CompiledSinks,
    CompiledSources,
    CompiledSummaries,
    CompiledNeutrals,
    __MODELES__,
    InterpretedSink,
    InterpretedSource,
    InterpretedSummary,
    InterpretedType,
    InterpretedTypeVariable,
)

LANGUAGE_TYPES = {"csharp": "Compiled", "java": "Compiled", "javascript": "Interpreted"}

logger = logging.getLogger("ghastoolkit.codeql.dataextensions")


@dataclass
class DataExtensions:
    language: str
    pack: Optional[str] = None
    paths: List[str] = field(default_factory=list)

    sources: List[Union[CompiledSources, InterpretedSource]] = field(
        default_factory=list
    )

    sinks: List[Union[CompiledSinks, InterpretedSink]] = field(default_factory=list)

    summaries: List[Union[CompiledSummaries, InterpretedSummary]] = field(
        default_factory=list
    )

    types: List[Union[InterpretedType, InterpretedTypeVariable]] = field(
        default_factory=list
    )

    neutrals: List[CompiledNeutrals] = field(default_factory=list)

    def __post_init__(self):
        if not self.pack:
            self.pack = f"codeql/{self.language}-queries"

    def load(self, path: str):
        if not os.path.exists(path):
            raise Exception(f"Path does not exist :: {path}")
        logger.debug(f"Loading data extension from path :: '{path}'")
        with open(path, "r") as handle:
            data = yaml.safe_load(handle)

        language_type = LANGUAGE_TYPES.get(self.language)

        for ext in data.get("extensions"):
            extensible = ext.get("addsTo", {}).get("extensible", "")
            ext_name = extensible.replace("Model", "")
            class_name = f"{language_type}{ext_name.title()}"
            clss = __MODELES__.get(class_name)
            if not clss:
                logger.error(f"Unknown class :: {class_name}")
                continue

            for data_ext in ext.get("data", []):
                i = clss(*data_ext)
                if ext_name == "source":
                    self.sources.append(i)
                elif ext_name == "sink":
                    self.sinks.append(i)
                elif ext_name == "summary":
                    self.summaries.append(i)
                elif ext_name == "neutral":
                    self.neutrals.append(i)
                elif ext_name == "type":
                    self.types.append(i)
                elif ext_name == "typeVariable":
                    self.types.append(i)
                else:
                    logger.warning(f"Unknown data extension :: {ext_name}")

        self.paths.append(path)
