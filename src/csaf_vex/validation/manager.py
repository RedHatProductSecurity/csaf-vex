"""Plugin manager for CSAF VEX validators."""

import logging
from importlib.metadata import entry_points

from csaf_vex.models import CSAFVEX
from csaf_vex.validation.base import ValidationPlugin, ValidationResult

logger = logging.getLogger(__name__)


class PluginManager:
    """Discovers and runs validators exposed via Python entry points."""

    PLUGIN_ENTRY_POINT_GROUP = "csaf_vex.validators"

    def __init__(self, log_level: int = logging.WARNING) -> None:
        self.log_level = log_level
        logger.setLevel(self.log_level)

    def _load(self) -> list[ValidationPlugin]:
        """Discover and instantiate all plugins."""

        discovered: list[ValidationPlugin] = []

        eps = entry_points(group=self.PLUGIN_ENTRY_POINT_GROUP)

        # Deterministic order by entry point name
        sorted_eps = sorted(eps, key=lambda ep: ep.name)

        for ep in sorted_eps:
            try:
                plugin_cls = ep.load()
                if not isinstance(plugin_cls, type) or not issubclass(plugin_cls, ValidationPlugin):
                    logger.warning(
                        "Skipping entry point '%s': not a subclass of ValidationPlugin (got %r)",
                        ep.name,
                        plugin_cls,
                    )
                    continue
                plugin = plugin_cls(log_level=self.log_level)
                discovered.append(plugin)
            except Exception as exc:
                logger.error(
                    "Failed to load validator plugin '%s': %s: %s",
                    ep.name,
                    type(exc).__name__,
                    exc,
                )

        return discovered

    def run(self, document: CSAFVEX) -> list[ValidationResult]:
        """Run all loaded plugins against the provided document."""
        plugins = self._load()

        results: list[ValidationResult] = []
        for plugin in plugins:
            results.append(plugin.validate(document))
        return results
