"""Base validation API for CSAF VEX plugins."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from time import perf_counter

from csaf_vex.models import CSAFVEXDocument


@dataclass
class ValidationError:
    """A validation finding produced by a validator.

    Attributes:
        message: Human-readable description of the issue.
    """

    message: str


@dataclass
class ValidationResult:
    """The aggregated outcome of a single validator's execution."""

    validator_name: str
    success: bool
    errors: list[ValidationError] = field(default_factory=list)
    duration_ms: int | None = None


class ValidationPlugin(ABC):
    """Base class for all validation plugins.

    Plugins should implement `_run_validation` and avoid raising exceptions.
    Unexpected exceptions are caught and converted into a failure result.
    """

    name: str = "unknown_plugin"
    description: str = "Validation plugin"

    def validate(self, document: CSAFVEXDocument) -> ValidationResult:
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
            crash = ValidationError(
                message=f"Plugin execution failed unexpectedly: {type(exc).__name__}: {exc}",
            )
            return ValidationResult(
                validator_name=self.name,
                success=False,
                errors=[crash],
                duration_ms=duration_ms,
            )

    @abstractmethod
    def _run_validation(self, document: CSAFVEXDocument) -> list[ValidationError]:
        """Perform validator-specific checks on the provided document and return findings."""
        raise NotImplementedError

    def __str__(self) -> str:
        return f"Plugin: {self.name} - {self.description}"
