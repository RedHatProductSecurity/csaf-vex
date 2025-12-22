"""Validation plugins framework for CSAF VEX documents.

This module provides the plugin API and orchestration for running external validation
plugins against CSAF VEX documents. Use the Validator to discover and run plugins
registered under the 'csaf_vex.validators' entry point group.

Usage:
    from csaf_vex.validation import Validator

    # Create a validator from a file and run all installed plugins
    validator = Validator.from_file("path/to/vex.json")
    report = validator.run_all()

    # Check if all plugins passed
    if report.passed:
        print("All validation plugins passed!")
    else:
        for result in report.results:
            if not result.success:
                print(f"{result.validator_name}:")
                for err in result.errors:
                    print(f"  - {err.message}")
"""

from .base import ValidationError, ValidationPlugin, ValidationResult
from .manager import PluginManager
from .result import ValidationReport
from .validator import Validator

__all__ = [
    "PluginManager",
    "ValidationError",
    "ValidationPlugin",
    "ValidationReport",
    "ValidationResult",
    "Validator",
]
