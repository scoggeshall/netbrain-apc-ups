"""Synthetic tests for runtime parsing and intent evaluation."""

import pytest

from netbrain_apc_ups.intents.runtime import RuntimeStatus, evaluate_runtime_intent
from netbrain_apc_ups.parsers.runtime import (
    MalformedRuntimeError,
    MissingRuntimeError,
    parse_remaining_runtime,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("00:45:30", 2730),
        ("1:02:03", 3723),
        ("1 day 2:03:04", 93784),
        ("1 day 2 hours 3 minutes 4 seconds", 93784),
        ("45 minutes", 2700),
        ("30 seconds", 30),
        ("2 hours 3 minutes", 7380),
    ],
)
def test_parses_labeled_runtime_values(value: str, expected: int) -> None:
    measurement = parse_remaining_runtime(f"Remaining Runtime: {value}\n")

    assert measurement.seconds == expected
    assert measurement.minutes == expected / 60
    assert measurement.raw_value == value


def test_parses_runtime_equals_label_case_insensitively() -> None:
    assert parse_remaining_runtime("runtime = 01:00:00").seconds == 3600


@pytest.mark.parametrize("output", ["", "Battery charge: 90%", "Status: Online"])
def test_missing_runtime_raises(output: str) -> None:
    with pytest.raises(MissingRuntimeError):
        parse_remaining_runtime(output)


@pytest.mark.parametrize(
    "value",
    ["", "60", "-1 minutes", "1:60:00", "1:00:60", "1 hour 2 minutes 3 hours", "unknown"],
)
def test_malformed_runtime_is_rejected(value: str) -> None:
    with pytest.raises(MalformedRuntimeError):
        parse_remaining_runtime(f"Runtime: {value}")


def test_ambiguous_multiple_runtime_fields_are_rejected() -> None:
    with pytest.raises(MalformedRuntimeError, match="Multiple"):
        parse_remaining_runtime("Runtime: 01:00:00\nRemaining Runtime: 00:30:00")


def test_runtime_exactly_at_threshold_passes() -> None:
    result = evaluate_runtime_intent("UPS-01", 3600)

    assert result.status is RuntimeStatus.PASS
    assert result.runtime_minutes == 60
    assert result.threshold_seconds == 3600
    assert result.to_dict()["status"] == "PASS"


def test_runtime_below_threshold_fails_even_with_warning_policy() -> None:
    result = evaluate_runtime_intent("UPS-01", 3599, warning_threshold_seconds=4200)

    assert result.status is RuntimeStatus.FAIL


def test_optional_warning_only_applies_above_pass_threshold() -> None:
    warning = evaluate_runtime_intent("UPS-01", 3900, warning_threshold_seconds=4200)
    passing = evaluate_runtime_intent("UPS-01", 4200, warning_threshold_seconds=4200)
    default = evaluate_runtime_intent("UPS-01", 3900)

    assert warning.status is RuntimeStatus.WARN
    assert passing.status is RuntimeStatus.PASS
    assert default.status is RuntimeStatus.PASS


@pytest.mark.parametrize("seconds", [0, 3599])
def test_runtime_below_default_threshold_fails(seconds: int) -> None:
    assert evaluate_runtime_intent("UPS-01", seconds).status is RuntimeStatus.FAIL


def test_missing_or_unsupported_runtime_preserves_status() -> None:
    missing = evaluate_runtime_intent("UPS-01", None, reason="No reading")
    unsupported = evaluate_runtime_intent(
        "UPS-01", None, unavailable_status=RuntimeStatus.UNSUPPORTED
    )

    assert missing.status is RuntimeStatus.UNKNOWN
    assert missing.runtime_minutes is None
    assert unsupported.status is RuntimeStatus.UNSUPPORTED


@pytest.mark.parametrize(
    ("runtime", "threshold", "warning"),
    [(-1, 3600, None), (0, 0, None), (3600, 3600, 3599)],
)
def test_invalid_threshold_or_measurement_is_rejected(
    runtime: int, threshold: int, warning: int | None
) -> None:
    with pytest.raises(ValueError):
        evaluate_runtime_intent(
            "UPS-01", runtime, threshold_seconds=threshold, warning_threshold_seconds=warning
        )
