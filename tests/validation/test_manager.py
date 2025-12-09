from csaf_vex.models import CSAFVEX
from csaf_vex.validation import manager as manager_mod
from csaf_vex.validation.base import ValidationError, ValidationPlugin
from csaf_vex.validation.manager import PluginManager


class MockEntryPoint:
    def __init__(self, name, obj=None, exc=None):
        self.name = name
        self._obj = obj
        self._exc = exc

    def load(self):
        if self._exc is not None:
            raise self._exc
        return self._obj


class APlugin(ValidationPlugin):
    name = "a"

    def _run_validation(self, document):
        return []


class BPlugin(ValidationPlugin):
    name = "b"

    def _run_validation(self, document):
        return [ValidationError(message="b failed")]


def test_manager_discovers_and_runs_in_sorted_order(monkeypatch, caplog, minimal_vex):
    eps = [MockEntryPoint("b", BPlugin), MockEntryPoint("a", APlugin)]
    monkeypatch.setattr(manager_mod, "entry_points", lambda group: eps)

    doc = CSAFVEX.from_dict(minimal_vex)
    results = PluginManager().run(doc)

    # Expect two results, ordered by entry point name: a, then b
    assert [r.validator_name for r in results] == ["a", "b"]
    assert results[0].success is True
    assert results[1].success is False
    assert results[1].errors and "b failed" in results[1].errors[0].message


def test_manager_logs_skip_for_non_plugin(monkeypatch, caplog, minimal_vex):
    class NotAPlugin:
        pass

    eps = [MockEntryPoint("not_plugin", NotAPlugin)]
    monkeypatch.setattr(manager_mod, "entry_points", lambda group: eps)

    caplog.set_level("WARNING")
    doc = CSAFVEX.from_dict(minimal_vex)
    results = PluginManager().run(doc)

    assert results == []
    assert any("Skipping entry point 'not_plugin'" in rec.message for rec in caplog.records)


def test_manager_logs_error_on_load_exception(monkeypatch, caplog, minimal_vex):
    eps = [MockEntryPoint("bad_plugin", exc=RuntimeError("cannot import"))]
    monkeypatch.setattr(manager_mod, "entry_points", lambda group: eps)

    caplog.set_level("ERROR")
    doc = CSAFVEX.from_dict(minimal_vex)
    results = PluginManager().run(doc)

    assert results == []  # no valid plugins
    assert any(
        "Failed to load validator plugin 'bad_plugin'" in rec.message for rec in caplog.records
    )
