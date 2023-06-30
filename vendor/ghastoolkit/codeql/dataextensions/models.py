from dataclasses import dataclass
from typing import List

MODELS_AS_DATA = {
    "CompiledSources": [
        "package",
        "type",
        "subtypes",
        "name",
        "signature",
        "ext",
        "output",
        "kind",
        "provenance",
    ],
    "CompiledSinks": [
        "package",
        "type",
        "subtypes",
        "name",
        "signature",
        "ext",
        "input",
        "kind",
        "provenance",
    ],
    "CompiledSummaries": [
        "package",
        "type",
        "subtypes",
        "name",
        "signature",
        "ext",
        "input",
        "output",
        "kind",
        "provenance",
    ],
    "CompiledNeutrals": ["package", "type", "name", "signature", "kind", "provenance"],
}


class ModelAsData:
    def generateMad(self, headers: List[str]) -> List[str]:
        result = []
        for header in headers:
            if hasattr(self, header):
                result.append(getattr(self, header))
            elif hasattr(self, f"object_{header}"):
                result.append(getattr(self, f"object_{header}"))
        return result

    def generate(self) -> List[str]:
        return self.generateMad(MODELS_AS_DATA.get(self.__class__.__name__, []))


@dataclass
class CompiledSources(ModelAsData):
    """Compile Sources"""

    package: str
    object_type: str
    subtypes: bool
    name: str
    signature: str
    ext: str
    output: str
    kind: str
    provenance: str = "manual"


@dataclass
class CompiledSinks(ModelAsData):
    """Compile Sources"""

    package: str
    object_type: str
    subtypes: bool
    name: str
    signature: str
    ext: str
    object_input: str
    kind: str
    provenance: str = "manual"


@dataclass
class CompiledSummaries(ModelAsData):
    """Compiled Summaries"""

    package: str
    object_type: str
    subtypes: bool
    name: str
    signature: str
    ext: str
    object_input: str
    output: str
    kind: str
    provenance: str = "manual"


@dataclass
class CompiledNeutrals(ModelAsData):
    """Compiled Neutrals"""

    package: str
    object_type: str
    name: str
    signature: str
    kind: str
    provenance: str = "manual"


@dataclass
class InterpretedSource(ModelAsData):
    """Interpreted Source"""

    object_type: str
    path: str
    kind: str


@dataclass
class InterpretedSink(ModelAsData):
    """Interpreted Sink"""

    object_type: str
    path: str
    kind: str


@dataclass
class InterpretedSummary(ModelAsData):
    """Interpreted Summary"""

    object_type: str
    path: str
    object_input: str
    output: str
    kind: str


@dataclass
class InterpretedType(ModelAsData):
    """Interpreted Type"""

    object_type1: str
    object_type2: str
    path: str


@dataclass
class InterpretedTypeVariable(ModelAsData):
    """Interpreted Type"""

    object_type1: str
    object_type2: str


__MODELES__ = {
    "CompiledSink": CompiledSinks,
    "CompiledSource": CompiledSources,
    "CompiledSummary": CompiledSummaries,
    "CompiledNeutral": CompiledNeutrals,
    "InterpretedSource": InterpretedSource,
    "InterpretedSink": InterpretedSink,
    "InterpretedSummary": InterpretedSummary,
    "InterpretedType": InterpretedType,
    "InterpretedTypevariable": InterpretedTypeVariable,
}
