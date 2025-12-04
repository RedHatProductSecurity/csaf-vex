"""VEX Verification module for CSAF VEX documents.

This module provides verification functionality for CSAF VEX documents,
implementing tests from two categories:

- Test Set 1 (CSAF Compliance): 14 tests verifying VEX Profile conformance
  and CSAF mandatory tests (Section 6.1)
- Test Set 2 (Data Type Checks): 16 tests verifying data format compliance,
  patterns, and schema constraints

Usage:
    from csaf_vex.verification import Verifier, VerificationReport

    # Create a verifier from a file
    verifier = Verifier.from_file("path/to/vex.json")

    # Run all tests
    report = verifier.run_all()

    # Check if verification passed
    if report.passed:
        print("All tests passed!")
    else:
        for failure in report.failures:
            print(f"{failure.test_id}: {failure.message}")

    # Run specific test sets
    csaf_report = verifier.run_csaf_compliance()
    data_report = verifier.run_data_type_checks()

    # Run a specific test
    result = verifier.run_test("1.1")
"""

from .csaf_compliance import ALL_CSAF_COMPLIANCE_TESTS
from .data_type_checks import ALL_DATA_TYPE_CHECKS
from .result import (
    VerificationReport,
    VerificationResult,
    VerificationSeverity,
    VerificationStatus,
)
from .verifier import Verifier

__all__ = [
    "ALL_CSAF_COMPLIANCE_TESTS",
    "ALL_DATA_TYPE_CHECKS",
    "VerificationReport",
    "VerificationResult",
    "VerificationSeverity",
    "VerificationStatus",
    "Verifier",
]
