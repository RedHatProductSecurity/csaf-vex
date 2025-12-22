"""Validator orchestrates running all installed validation plugins against a CSAF VEX document.

This is analogous in spirit to the Verifier (structural checks), but focused on
running third-party/plugin validations. It intentionally has no raw-content or
file-size handling.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from csaf_vex.models import CSAFVEX
from csaf_vex.validation.manager import PluginManager
from csaf_vex.validation.result import ValidationReport


class Validator:
    """Orchestrates discovery and execution of validation plugins."""

    def __init__(self, document: CSAFVEX, log_level: int = logging.WARNING) -> None:
        self._doc = document
        self._log_level = log_level
        self._document_id = None
        try:
            # Nested model path per internal representation
            self._document_id = (
                self._doc.document.tracking.id
                if self._doc.document and self._doc.document.tracking
                else None
            )
        except Exception:
            self._document_id = None

    @classmethod
    def from_file(cls, filepath: str | Path, *, log_level: int = logging.WARNING) -> Validator:
        """Create a Validator from a JSON file path."""
        csafvex = CSAFVEX.from_file(filepath)
        return cls(csafvex, log_level=log_level)

    @classmethod
    def from_json(
        cls,
        json_input: str | dict[str, Any],
        *,
        log_level: int = logging.WARNING,
    ) -> Validator:
        """Create a Validator from a JSON string or a parsed dictionary."""
        if isinstance(json_input, str):
            csafvex = CSAFVEX.from_dict(json.loads(json_input))
        else:
            csafvex = CSAFVEX.from_dict(json_input)
        return cls(csafvex, log_level=log_level)

    def run_all(self) -> ValidationReport:
        """Discover and run all validation plugins."""
        manager = PluginManager(log_level=self._log_level)
        results = manager.run(self._doc)
        report = ValidationReport(document_id=self._document_id)
        report.add_results(results)
        return report

    def run_plugins(self, names: list[str]) -> ValidationReport:
        """Run only the specified plugin names (by plugin.name).

        # TODO: Update PluginManager to support running only selected plugin names
        # to avoid running all plugins and filtering results post-execution.
        """
        target = set(names)
        full_report = self.run_all()
        filtered = [r for r in full_report.results if r.validator_name in target]
        return ValidationReport(results=filtered, document_id=full_report.document_id)

    @staticmethod
    def get_available_plugins() -> list[str]:
        """Return discovered plugin names (sorted by entry point name)."""
        # Reuse manager discovery to avoid running plugins
        manager = PluginManager()
        try:
            # Access internal loader for discovery without execution
            plugins = manager._load()  # type: ignore[attr-defined]
            return sorted(getattr(p, "name", "unknown_plugin") for p in plugins)
        except Exception:
            return []
