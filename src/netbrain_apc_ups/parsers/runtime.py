"""Runtime parsing independent of any network transport."""

from __future__ import annotations

import re
from dataclasses import dataclass


class RuntimeParseError(ValueError):
    """Base error for invalid or absent runtime measurements."""


class MissingRuntimeError(RuntimeParseError):
    """Raised when CLI output contains no recognizable runtime field."""


class MalformedRuntimeError(RuntimeParseError):
    """Raised when a runtime field is ambiguous or cannot be parsed safely."""


@dataclass(frozen=True)
class RuntimeMeasurement:
    """Remaining runtime normalized to seconds, preserving the CLI value."""

    seconds: int
    raw_value: str

    @property
    def minutes(self) -> float:
        """Return runtime in fractional minutes."""
        return self.seconds / 60


_FIELD = re.compile(
    r"^\s*(?:estimated\s+)?(?:remaining\s+)?runtime\s*[:=]\s*(.*?)\s*$",
    re.IGNORECASE,
)
_CLOCK = re.compile(r"(?:(\d+)\s+days?\s+)?(\d+):(\d{1,2}):(\d{1,2})")
_UNITS = re.compile(
    r"^\s*(?:(\d+)\s*days?\s*)?"
    r"(?:(\d+)\s*hours?\s*)?"
    r"(?:(\d+)\s*minutes?\s*)?"
    r"(?:(\d+)\s*seconds?\s*)?$",
    re.IGNORECASE,
)


def _parse_value(raw_value: str) -> int:
    value = raw_value.strip()
    if not value:
        raise MalformedRuntimeError("Runtime field is empty")

    clock_match = _CLOCK.fullmatch(value)
    if clock_match:
        days, hours, minutes, seconds = clock_match.groups()
        hours_value = int(hours)
        minutes_value = int(minutes)
        seconds_value = int(seconds)
        if minutes_value >= 60 or seconds_value >= 60:
            raise MalformedRuntimeError(f"Invalid clock runtime: {value!r}")
        total_hours = (int(days or 0) * 24) + hours_value
        return total_hours * 3600 + minutes_value * 60 + seconds_value

    if re.fullmatch(r"\d+", value):
        raise MalformedRuntimeError("Unitless runtime values are ambiguous")

    unit_match = _UNITS.fullmatch(value)
    if not unit_match or not any(unit_match.groups()):
        raise MalformedRuntimeError(f"Unrecognized runtime value: {value!r}")

    days, hours, minutes, seconds = (int(part or 0) for part in unit_match.groups())
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def parse_remaining_runtime(output: str) -> RuntimeMeasurement:
    """Parse one labeled runtime from CLI output.

    Supported forms include ``Remaining Runtime: 00:45:30``,
    ``Runtime: 1:02:03``, and labeled values with explicit day/hour/minute/second
    units. These formats are covered by synthetic tests; firmware-specific device
    output still requires validation against sanitized captures.
    """
    if not isinstance(output, str):
        raise TypeError("CLI output must be a string")

    values = [
        match.group(1).strip() for line in output.splitlines() if (match := _FIELD.match(line))
    ]
    if not values:
        raise MissingRuntimeError("No runtime field found")
    if len(values) != 1:
        raise MalformedRuntimeError("Multiple runtime fields found; refusing ambiguous output")

    raw_value = values[0]
    return RuntimeMeasurement(seconds=_parse_value(raw_value), raw_value=raw_value)
