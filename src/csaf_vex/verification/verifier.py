import json
import logging
from pathlib import Path
from typing import Any, ClassVar

from csaf_vex.models import CSAFVEX

from .csaf_compliance import ALL_CSAF_COMPLIANCE_TESTS
from .data_type_checks import ALL_DATA_TYPE_CHECKS, verify_soft_limit_file_size
from .result import (
    VerificationReport,
    VerificationResult,
    VerificationSeverity,
    VerificationStatus,
)

logger = logging.getLogger(__name__)


class Verifier:
    """Orchestrates VEX document verification tests.

    This class provides methods to run all verification tests or specific
    test sets against a CSAF VEX document.

    Attributes:
        document: The document dict being verified
        document_id: The document tracking ID
    """

    # Map test IDs to their functions
    _TEST_REGISTRY: ClassVar[dict[str, Any]] = {}

    def __init__(
        self,
        document: CSAFVEX | dict[str, Any] | str | Path,
        raw_content: bytes | str | None = None,
        log_level: int = logging.WARNING,
    ) -> None:
        """Initialize the Verifier with a document.

        Args:
            document: Either a CSAFVEX model, parsed dictionary, JSON string, or Path to a JSON file
            raw_content: Optional raw bytes/string content for file size validation
            log_level: Logging level for verifier internals (default: WARNING)
        """
        # Parse to CSAFVEX model if needed and always keep the dict representation
        logger.setLevel(log_level)
        if isinstance(document, CSAFVEX):
            self._csafvex = document
            self._document = document.raw_data if document.raw_data else {}
            self._raw_content = raw_content
        elif isinstance(document, Path):
            with open(document) as f:
                self._raw_content = f.read()
                self._document = json.loads(self._raw_content)
                self._csafvex = CSAFVEX.from_dict(self._document)
        elif isinstance(document, str):
            self._raw_content = document
            self._document = json.loads(document)
            self._csafvex = CSAFVEX.from_dict(self._document)
        else:
            self._document = document
            self._csafvex = CSAFVEX.from_dict(document)
            self._raw_content = raw_content

        self._document_id = self._extract_document_id()

        # Build test registry if not already done
        if not Verifier._TEST_REGISTRY:
            Verifier._build_test_registry()
        logger.debug("Initialized Verifier (document_id=%r)", self._document_id)

    def _extract_document_id(self) -> str | None:
        """Extract the document tracking ID."""
        return self._document.get("document", {}).get("tracking", {}).get("id")

    @classmethod
    def _build_test_registry(cls) -> None:
        """Build a registry mapping test IDs to their functions."""
        # Register CSAF compliance tests (1.1 - 1.14)
        for i, test_func in enumerate(ALL_CSAF_COMPLIANCE_TESTS, start=1):
            test_id = f"1.{i}"
            cls._TEST_REGISTRY[test_id] = ("csaf_compliance", test_func)

        # Register data type checks (2.1 - 2.16)
        for i, test_func in enumerate(ALL_DATA_TYPE_CHECKS, start=1):
            test_id = f"2.{i}"
            cls._TEST_REGISTRY[test_id] = ("data_type_checks", test_func)
        logger.debug("Built test registry with %d tests", len(cls._TEST_REGISTRY))

    @property
    def document(self) -> dict[str, Any]:
        """Get the document being verified."""
        return self._document

    @property
    def document_id(self) -> str | None:
        """Get the document tracking ID."""
        return self._document_id

    def run_all(self) -> VerificationReport:
        """Run all verification tests.

        Returns:
            A VerificationReport containing results from all tests.
        """
        report = VerificationReport(document_id=self._document_id)

        # Run CSAF compliance tests
        logger.debug("Running CSAF compliance tests")
        csaf_report = self.run_csaf_compliance()
        report.add_results(csaf_report.results)

        # Run data type checks
        logger.debug("Running data type checks")
        data_report = self.run_data_type_checks()
        report.add_results(data_report.results)

        logger.debug(
            "Completed run_all: passed=%d failed=%d warn=%d skipped=%d",
            report.passed_count,
            report.failed_count,
            report.warning_count,
            report.skipped_count,
        )
        return report

    def run_csaf_compliance(self) -> VerificationReport:
        """Run only Test Set 1: CSAF Standard Compliance tests.

        Returns:
            A VerificationReport containing results from CSAF compliance tests.
        """
        report = VerificationReport(document_id=self._document_id)

        for test_func in ALL_CSAF_COMPLIANCE_TESTS:
            try:
                result = test_func(self._document)
                report.add_result(result)
            except Exception as e:
                # Create an error result for unexpected exceptions
                test_name = test_func.__doc__.split("\n")[0] if test_func.__doc__ else "Unknown"
                logger.exception("CSAF compliance test raised exception: %s", test_name)
                report.add_result(
                    VerificationResult(
                        test_id=getattr(test_func, "__name__", "unknown"),
                        test_name=test_name,
                        status=VerificationStatus.FAIL,
                        message=f"Test raised an exception: {e!s}",
                        severity=VerificationSeverity.ERROR,
                        source_ref="Internal Error",
                        details={"exception": str(e), "exception_type": type(e).__name__},
                    )
                )

        return report

    def run_data_type_checks(self) -> VerificationReport:
        """Run only Test Set 2: Data Type Checking tests.

        Returns:
            A VerificationReport containing results from data type checks.
        """
        report = VerificationReport(document_id=self._document_id)

        for test_func in ALL_DATA_TYPE_CHECKS:
            try:
                # Special handling for file size check which needs raw content
                if test_func is verify_soft_limit_file_size:
                    result = test_func(self._document, self._raw_content)
                else:
                    result = test_func(self._document)
                report.add_result(result)
            except Exception as e:
                # Create an error result for unexpected exceptions
                test_name = test_func.__doc__.split("\n")[0] if test_func.__doc__ else "Unknown"
                logger.exception("Data type check raised exception: %s", test_name)
                report.add_result(
                    VerificationResult(
                        test_id=getattr(test_func, "__name__", "unknown"),
                        test_name=test_name,
                        status=VerificationStatus.FAIL,
                        message=f"Test raised an exception: {e!s}",
                        severity=VerificationSeverity.ERROR,
                        source_ref="Internal Error",
                        details={"exception": str(e), "exception_type": type(e).__name__},
                    )
                )

        return report

    def run_test(self, test_id: str) -> VerificationResult:
        """Run a specific test by ID.

        Args:
            test_id: The test ID (e.g., "1.1", "2.5")

        Returns:
            The VerificationResult for the specified test.

        Raises:
            ValueError: If the test_id is not found.
        """
        if test_id not in self._TEST_REGISTRY:
            available = sorted(self._TEST_REGISTRY.keys())
            raise ValueError(f"Unknown test ID: {test_id}. Available tests: {available}")

        _, test_func = self._TEST_REGISTRY[test_id]

        # Special handling for file size check
        if test_id == "2.13":  # verify_soft_limit_file_size
            return test_func(self._document, self._raw_content)

        return test_func(self._document)

    def run_tests(self, test_ids: list[str]) -> VerificationReport:
        """Run multiple specific tests by ID.

        Args:
            test_ids: List of test IDs to run (e.g., ["1.1", "1.2", "2.5"])

        Returns:
            A VerificationReport containing results from the specified tests.
        """
        report = VerificationReport(document_id=self._document_id)

        for test_id in test_ids:
            try:
                result = self.run_test(test_id)
                report.add_result(result)
            except ValueError as e:
                report.add_result(
                    VerificationResult(
                        test_id=test_id,
                        test_name="Unknown Test",
                        status=VerificationStatus.SKIP,
                        message=str(e),
                        severity=VerificationSeverity.WARNING,
                        source_ref="Unknown",
                    )
                )

        return report

    @classmethod
    def get_available_tests(cls) -> dict[str, str]:
        """Get a dictionary of all available test IDs and their names.

        Returns:
            Dictionary mapping test IDs to test names.
        """
        if not cls._TEST_REGISTRY:
            cls._build_test_registry()

        result = {}
        for test_id, (_, test_func) in cls._TEST_REGISTRY.items():
            # Extract test name from docstring
            if test_func.__doc__:
                first_line = test_func.__doc__.split("\n")[0]
                # Remove "Test X.X: " prefix if present
                if ":" in first_line:
                    name = first_line.split(":", 1)[1].strip()
                else:
                    name = first_line.strip()
            else:
                name = test_func.__name__
            result[test_id] = name

        return result

    @classmethod
    def from_file(cls, filepath: str | Path, *, log_level: int = logging.WARNING) -> "Verifier":
        """Create a Verifier from a JSON file path.

        Args:
            filepath: Path to a CSAF VEX JSON file
            log_level: Logging level for verifier internals

        Returns:
            A Verifier instance for the file
        """
        return cls(Path(filepath), log_level=log_level)

    @classmethod
    def from_json(cls, json_string: str, *, log_level: int = logging.WARNING) -> "Verifier":
        """Create a Verifier from a JSON string.

        Args:
            json_string: A JSON string containing a CSAF VEX document
            log_level: Logging level for verifier internals

        Returns:
            A Verifier instance for the document
        """
        return cls(json_string, log_level=log_level)
