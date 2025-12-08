"""Result data structures for validation plugin execution."""

from typing import Any

import attrs

from csaf_vex.validation.base import ValidationResult


@attrs.define
class ValidationReport:
    """Aggregated results from running validation plugins.

    Attributes:
        results: List of individual validation results from plugins
        document_id: Optional identifier for the validated document
    """

    results: list[ValidationResult] = attrs.field(factory=list)
    document_id: str | None = attrs.field(default=None)

    def add_result(self, result: ValidationResult) -> None:
        """Add a validation result to the report."""
        self.results.append(result)

    def add_results(self, results: list[ValidationResult]) -> None:
        """Add multiple validation results to the report."""
        self.results.extend(results)

    @property
    def total(self) -> int:
        """Get the total number of plugin results."""
        return len(self.results)

    @property
    def passed_count(self) -> int:
        """Get the number of successful plugin results."""
        return sum(1 for r in self.results if r.success)

    @property
    def failed_count(self) -> int:
        """Get the number of failed plugin results."""
        return sum(1 for r in self.results if not r.success)

    @property
    def passed(self) -> bool:
        """Check if all plugins passed (no failures)."""
        return self.failed_count == 0

    def to_dict(self) -> dict[str, Any]:
        """Convert the report to a dictionary."""
        return {
            "document_id": self.document_id,
            "summary": {
                "total": self.total,
                "passed": self.passed_count,
                "failed": self.failed_count,
            },
            "passed": self.passed,
            "results": [attrs.asdict(r) for r in self.results],
        }
