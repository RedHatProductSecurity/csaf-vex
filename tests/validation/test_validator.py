import pytest

from csaf_vex.models import CSAFVEX
from csaf_vex.validation.base import ValidationError, ValidationResult
from csaf_vex.validation.validator import Validator


@pytest.fixture
def csafvex_minimal(minimal_vex):
    """Build a minimal CSAFVEX model from fixture dict."""
    return CSAFVEX.from_dict(minimal_vex)


def test_run_all_with_no_plugins_returns_empty_report(monkeypatch, csafvex_minimal):
    """Validator.run_all should return an empty, passing report when no plugins are present."""
    # Monkeypatch PluginManager.run to return an empty list
    from csaf_vex.validation import validator as validator_mod

    class DummyManager:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, document):
            return []

    monkeypatch.setattr(validator_mod, "PluginManager", DummyManager)

    report = Validator(csafvex_minimal).run_all()
    assert report.total == 0
    assert report.passed is True
    assert report.failed_count == 0


def test_run_plugins_filters_results(monkeypatch, csafvex_minimal):
    """Validator.run_plugins should filter results by validator_name."""
    # Prepare three fake results
    results = [
        ValidationResult(validator_name="a", success=True, errors=[], duration_ms=1),
        ValidationResult(
            validator_name="b", success=False, errors=[ValidationError("err")], duration_ms=2
        ),
        ValidationResult(validator_name="c", success=True, errors=[], duration_ms=3),
    ]

    from csaf_vex.validation import validator as validator_mod

    class DummyManager:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, document):
            return results

    monkeypatch.setattr(validator_mod, "PluginManager", DummyManager)

    report = Validator(csafvex_minimal).run_plugins(["a", "c"])
    names = [r.validator_name for r in report.results]
    assert names == ["a", "c"]
    assert report.total == 2
    assert report.failed_count == 0
    assert report.passed is True


def test_get_available_plugins_names(monkeypatch):
    """Validator.get_available_plugins should list discovered plugin names."""
    from csaf_vex.validation import validator as validator_mod

    class FakePlugin:
        name = "fake_plugin"

    class DummyManager:
        def __init__(self, *args, **kwargs):
            pass

        def _load(self):
            return [FakePlugin()]

    monkeypatch.setattr(validator_mod, "PluginManager", DummyManager)

    names = Validator.get_available_plugins()
    assert names == ["fake_plugin"]
