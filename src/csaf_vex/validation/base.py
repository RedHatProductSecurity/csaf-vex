"""Base validation API for CSAF VEX plugins."""

import logging
from abc import ABC, abstractmethod
from time import perf_counter

import attrs

from csaf_vex.models import CSAFVEX


@attrs.define
class ValidationError:
    """A validation finding produced by a validator.

    Attributes:
        message: Human-readable description of the issue.
    """

    message: str


@attrs.define
class ValidationResult:
    """The aggregated outcome of a single validator's execution."""

    validator_name: str
    success: bool
    errors: list[ValidationError] = attrs.field(factory=list)
    duration_ms: int | None = attrs.field(default=None)


class ValidationPlugin(ABC):
    """Base class for all validation plugins.

    Plugins should implement `_run_validation` and avoid raising exceptions.
    Unexpected exceptions are caught and converted into a failure result.
    """

    name: str = "unknown_plugin"
    description: str = "Validation plugin"

    def __init__(self, log_level: int = logging.WARNING) -> None:
        logger_name = f"csaf_vex.plugins.{self.name}"
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(log_level)

    def validate(self, document: CSAFVEX) -> ValidationResult:
        """Execute validation on the parsed CSAF VEX document."""

        start = perf_counter()
        try:
            findings = self._run_validation(document)
            success = not findings
            duration_ms = int((perf_counter() - start) * 1000)
            return ValidationResult(
                validator_name=self.name,
                success=success,
                errors=findings,
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((perf_counter() - start) * 1000)
            error = ValidationError(
                message=f"Plugin execution failed unexpectedly: {type(exc).__name__}: {exc}",
            )
            return ValidationResult(
                validator_name=self.name,
                success=False,
                errors=[error],
                duration_ms=duration_ms,
            )

    @abstractmethod
    def _run_validation(self, document: CSAFVEX) -> list[ValidationError]:
        """Perform validator-specific checks on the provided document and return findings."""
        raise NotImplementedError

    def __str__(self) -> str:
        return f"Plugin: {self.name} - {self.description}"
