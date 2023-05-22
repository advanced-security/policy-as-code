from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CodeLocation:
    uri: str

    start_line: int
    start_column: Optional[int] = None
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def __str__(self) -> str:
        return f"{self.uri}#{self.start_line}"


@dataclass
class CodeResult:
    rule_id: str
    message: str

    locations: list[CodeLocation] = field(default_factory=list)

    def __str__(self) -> str:
        if len(self.locations) == 1:
            return f"CodeResult('{self.rule_id}', '{self.locations[0]}')"
        return f"CodeResult('{self.rule_id}', {len(self.locations)})"

    @staticmethod
    def loadSarifLocations(data: list[dict]) -> list["CodeLocation"]:
        locations = []
        for loc in data:
            physical = loc.get("physicalLocation", {})
            region = physical.get("region", {})
            locations.append(
                CodeLocation(
                    physical.get("artifactLocation", {}).get("uri", ""),
                    start_line=region.get("startLine", "0"),
                    start_column=region.get("startColumn"),
                    end_line=region.get("endLine"),
                    end_column=region.get("endColumn"),
                )
            )
        return locations


class CodeQLResults(list):
    @staticmethod
    def loadSarifResults(results: list[dict]) -> "CodeQLResults":
        result = CodeQLResults()

        for alert in results:
            result.append(
                CodeResult(
                    alert.get("ruleId", "NA"),
                    alert.get("message", {}).get("text", "NA"),
                    locations=CodeResult.loadSarifLocations(alert.get("locations", [])),
                )
            )

        return result
