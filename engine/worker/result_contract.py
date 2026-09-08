"""Strict policy outcomes and the versioned Phase 3 score contract."""

from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

ResultStatus = Literal[
    "passed", "failed", "indeterminate", "error", "skipped", "not_assessable"
]
TERMINAL_STATES = (
    "passed",
    "failed",
    "indeterminate",
    "error",
    "skipped",
    "not_assessable",
)


class OPAResult(BaseModel):
    """Only explicit JSON booleans are determinate assessments."""

    model_config = ConfigDict(strict=True, extra="forbid")
    compliant: bool | None
    message: str
    affected_resources: list[Any]
    details: dict[str, Any]

    @property
    def status(self) -> ResultStatus:
        if self.compliant is None:
            return "indeterminate"
        return "passed" if self.compliant else "failed"


def calculate_scores(
    counts: dict[str, int], selected: int | None
) -> tuple[Decimal | None, Decimal | None]:
    """Assessments determine compliance; the frozen selection determines coverage."""
    passed = counts.get("passed", 0)
    assessed = passed + counts.get("failed", 0)

    def percentage(numerator: int, denominator: int | None) -> Decimal | None:
        if not denominator:
            return None
        return (Decimal(numerator) * 100 / Decimal(denominator)).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )

    return percentage(passed, assessed), percentage(assessed, selected)
