"""Evaluation of the configurable minimum remaining-runtime intent."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum


class RuntimeStatus(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class RuntimeIntentResult:
    device: str
    intent: str
    metric: str
    runtime_seconds: int | None
    runtime_minutes: float | None
    threshold_seconds: int
    status: RuntimeStatus
    source: str
    source_command: str | None
    raw_value: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, str | int | float | None]:
        """Return a JSON-serializable mapping."""
        result = asdict(self)
        result["status"] = self.status.value
        return result


def evaluate_runtime_intent(
    device_name: str,
    runtime_seconds: int | None,
    threshold_seconds: int = 3600,
    warning_threshold_seconds: int | None = None,
    source_command: str | None = "detstatus -rt",
    raw_value: str | None = None,
    unavailable_status: RuntimeStatus = RuntimeStatus.UNKNOWN,
    reason: str | None = None,
) -> RuntimeIntentResult:
    """Evaluate remaining runtime without allowing warning policy to mask failure.

    An optional warning threshold must be at least the pass threshold. Values
    below the pass threshold always fail; values between the pass and warning
    thresholds warn.
    """
    if threshold_seconds <= 0:
        raise ValueError("threshold_seconds must be positive")
    if warning_threshold_seconds is not None and warning_threshold_seconds < threshold_seconds:
        raise ValueError("warning_threshold_seconds must be >= threshold_seconds")
    if runtime_seconds is not None and runtime_seconds < 0:
        raise ValueError("runtime_seconds cannot be negative")
    if runtime_seconds is None:
        if unavailable_status not in (RuntimeStatus.UNKNOWN, RuntimeStatus.UNSUPPORTED):
            raise ValueError("Unavailable runtime status must be UNKNOWN or UNSUPPORTED")
        status = unavailable_status
    elif runtime_seconds < threshold_seconds:
        status = RuntimeStatus.FAIL
    elif warning_threshold_seconds is not None and runtime_seconds < warning_threshold_seconds:
        status = RuntimeStatus.WARN
    else:
        status = RuntimeStatus.PASS

    return RuntimeIntentResult(
        device=device_name,
        intent="APC UPS Runtime - Minimum 60 Minutes",
        metric="remaining_runtime",
        runtime_seconds=runtime_seconds,
        runtime_minutes=runtime_seconds / 60 if runtime_seconds is not None else None,
        threshold_seconds=threshold_seconds,
        status=status,
        source="APC CLI",
        source_command=source_command,
        raw_value=raw_value,
        reason=reason,
    )
