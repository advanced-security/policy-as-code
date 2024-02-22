"""CodeQL Results."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CodeLocation:
    """Code Location Module."""

    uri: str
    """URI to the location where the result occurs"""

    start_line: int
    """Start line of the result"""
    start_column: Optional[int] = None
    """Start column of the result"""
    end_line: Optional[int] = None
    """End line of the result"""
    end_column: Optional[int] = None
    """End line of the result"""

    def __str__(self) -> str:
        """To String."""
        return f"{self.uri}#{self.start_line}"


@dataclass
class CodeResult:
    """Code Result."""

    rule_id: str
    """Rule ID"""
    message: str
    """Message of the result"""

    locations: list[CodeLocation] = field(default_factory=list)
    """Locations of the results"""

    def __str__(self) -> str:
        """To String."""
        if len(self.locations) == 1:
            return f"CodeResult('{self.rule_id}', '{self.locations[0]}')"
        return f"CodeResult('{self.rule_id}', {len(self.locations)})"

    @staticmethod
    def loadSarifLocations(data: list[dict]) -> list["CodeLocation"]:
        """Load SARIF Locations."""
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
    """CodeQL Results."""

    @staticmethod
    def loadSarifResults(results: list[dict]) -> "CodeQLResults":
        """Load SARIF Results."""
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
