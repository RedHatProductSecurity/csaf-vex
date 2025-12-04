"""Result data structures for VEX verification."""

from enum import Enum
from typing import Any

import attrs


class VerificationStatus(str, Enum):
    """Status of a verification test."""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    WARN = "warn"


class VerificationSeverity(str, Enum):
    """Severity level of a verification result."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@attrs.define
class VerificationResult:
    """Represents the result of a single verification test.

    Attributes:
        test_id: Unique identifier for the test (e.g., "1.1", "2.5")
        test_name: Human-readable name of the test
        status: Pass/fail/skip/warn status
        message: Human-readable description of the result
        severity: Error/warning/info severity level
        source_ref: CSAF specification reference (e.g., "CSAF VEX Profile (4.5)")
        details: Optional additional details about the failure
    """

    test_id: str
    test_name: str
    status: VerificationStatus
    message: str
    severity: VerificationSeverity
    source_ref: str
    details: dict[str, Any] | None = attrs.field(default=None)

    @property
    def passed(self) -> bool:
        """Check if the test passed."""
        return self.status == VerificationStatus.PASS

    @property
    def failed(self) -> bool:
        """Check if the test failed."""
        return self.status == VerificationStatus.FAIL

    def to_dict(self) -> dict[str, Any]:
        """Convert the result to a dictionary."""
        result = {
            "test_id": self.test_id,
            "test_name": self.test_name,
            "status": self.status.value,
            "message": self.message,
            "severity": self.severity.value,
            "source_ref": self.source_ref,
        }
        if self.details:
            result["details"] = self.details
        return result


@attrs.define
class VerificationReport:
    """Represents a complete verification report containing multiple test results.

    Attributes:
        results: List of individual verification results
        document_id: Optional identifier for the verified document
    """

    results: list[VerificationResult] = attrs.field(factory=list)
    document_id: str | None = attrs.field(default=None)

    def add_result(self, result: VerificationResult) -> None:
        """Add a verification result to the report."""
        self.results.append(result)

    def add_results(self, results: list[VerificationResult]) -> None:
        """Add multiple verification results to the report."""
        self.results.extend(results)

    @property
    def passed(self) -> bool:
        """Check if all tests passed (no failures)."""
        return not any(r.failed for r in self.results)

    @property
    def total_tests(self) -> int:
        """Get the total number of tests run."""
        return len(self.results)

    @property
    def passed_count(self) -> int:
        """Get the number of passed tests."""
        return sum(1 for r in self.results if r.status == VerificationStatus.PASS)

    @property
    def failed_count(self) -> int:
        """Get the number of failed tests."""
        return sum(1 for r in self.results if r.status == VerificationStatus.FAIL)

    @property
    def warning_count(self) -> int:
        """Get the number of warnings."""
        return sum(1 for r in self.results if r.status == VerificationStatus.WARN)

    @property
    def skipped_count(self) -> int:
        """Get the number of skipped tests."""
        return sum(1 for r in self.results if r.status == VerificationStatus.SKIP)

    @property
    def failures(self) -> list[VerificationResult]:
        """Get all failed results."""
        return [r for r in self.results if r.failed]

    @property
    def warnings(self) -> list[VerificationResult]:
        """Get all warning results."""
        return [r for r in self.results if r.status == VerificationStatus.WARN]

    def get_results_by_test_set(self, prefix: str) -> list[VerificationResult]:
        """Get results for a specific test set (e.g., "1." for CSAF compliance)."""
        return [r for r in self.results if r.test_id.startswith(prefix)]

    def to_dict(self) -> dict[str, Any]:
        """Convert the report to a dictionary."""
        return {
            "document_id": self.document_id,
            "summary": {
                "total": self.total_tests,
                "passed": self.passed_count,
                "failed": self.failed_count,
                "warnings": self.warning_count,
                "skipped": self.skipped_count,
            },
            "passed": self.passed,
            "results": [r.to_dict() for r in self.results],
        }

    def __str__(self) -> str:
        """Return a human-readable summary of the report."""
        status = "PASSED" if self.passed else "FAILED"
        return (
            f"Verification Report: {status}\n"
            f"  Total: {self.total_tests}, Passed: {self.passed_count}, "
            f"Failed: {self.failed_count}, Warnings: {self.warning_count}, "
            f"Skipped: {self.skipped_count}"
        )
