from csaf_vex.models import CSAFVEX
from csaf_vex.validation.base import ValidationError, ValidationPlugin


class PassPlugin(ValidationPlugin):
    name = "pass_plugin"
    description = "Always passes"

    def _run_validation(self, document):
        return []


class FailPlugin(ValidationPlugin):
    name = "fail_plugin"
    description = "Always fails"

    def _run_validation(self, document):
        return [ValidationError(message="failed")]


class CrashPlugin(ValidationPlugin):
    name = "crash_plugin"
    description = "Raises an exception"

    def _run_validation(self, document):
        raise RuntimeError("boom")


def test_validate_pass(minimal_vex):
    doc = CSAFVEX.from_dict(minimal_vex)
    result = PassPlugin().validate(doc)
    assert result.validator_name == "pass_plugin"
    assert result.success is True
    assert result.errors == []
    assert isinstance(result.duration_ms, int)


def test_validate_fail(minimal_vex):
    doc = CSAFVEX.from_dict(minimal_vex)
    result = FailPlugin().validate(doc)
    assert result.validator_name == "fail_plugin"
    assert result.success is False
    assert len(result.errors) == 1
    assert "failed" in result.errors[0].message


def test_validate_crash_converted_to_error(minimal_vex):
    doc = CSAFVEX.from_dict(minimal_vex)
    result = CrashPlugin().validate(doc)
    assert result.validator_name == "crash_plugin"
    assert result.success is False
    assert len(result.errors) == 1
    assert "Plugin execution failed unexpectedly" in result.errors[0].message
