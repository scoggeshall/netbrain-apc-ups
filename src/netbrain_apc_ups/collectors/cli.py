"""Fixed-command APC CLI collection with no arbitrary command interface."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from netbrain_apc_ups.intents.runtime import (
    RuntimeIntentResult,
    RuntimeStatus,
    evaluate_runtime_intent,
)
from netbrain_apc_ups.parsers.runtime import RuntimeParseError, parse_remaining_runtime

logger = logging.getLogger(__name__)


class ReadOnlyCommand(str, Enum):
    RUNTIME = "detstatus -rt"
    DETAILS = "detstatus -all"


# This allowlist is deliberately limited to the two runtime-intent commands.
# Broader CLI safety/firmware compatibility verification remains outstanding.
ALLOWED_COMMANDS = frozenset(ReadOnlyCommand)


class CliTransport(Protocol):
    """Transport contract; implementations must honor the provided timeout."""

    def execute_read_only(self, command: str, timeout_seconds: float) -> str: ...


@dataclass(frozen=True)
class CliCollection:
    runtime: RuntimeIntentResult
    commands_attempted: tuple[str, ...]


class UnsupportedCommandError(Exception):
    """Transport explicitly reported an unsupported approved command."""


class CliCollector:
    """Collect the runtime intent through a fixed, read-only command sequence."""

    def __init__(self, transport: CliTransport, timeout_seconds: float = 15.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._transport = transport
        self._timeout_seconds = timeout_seconds

    def collect_runtime(
        self,
        device_name: str,
        threshold_seconds: int = 3600,
        warning_threshold_seconds: int | None = None,
    ) -> CliCollection:
        attempted: list[str] = []
        unsupported_count = 0
        last_reason = "Runtime measurement unavailable"
        for command in (ReadOnlyCommand.RUNTIME, ReadOnlyCommand.DETAILS):
            attempted.append(command.value)
            try:
                output = self._transport.execute_read_only(command.value, self._timeout_seconds)
            except UnsupportedCommandError:
                unsupported_count += 1
                last_reason = f"{command.value} is not supported by this device"
                logger.info("Approved APC command is unsupported: %s", command.value)
                continue
            except (TimeoutError, OSError) as error:
                status = RuntimeStatus.UNKNOWN
                last_reason = (
                    "CLI collection timed out"
                    if isinstance(error, TimeoutError)
                    else "CLI connection failed"
                )
                return CliCollection(
                    runtime=evaluate_runtime_intent(
                        device_name,
                        None,
                        threshold_seconds,
                        warning_threshold_seconds,
                        source_command=command.value,
                        unavailable_status=status,
                        reason=last_reason,
                    ),
                    commands_attempted=tuple(attempted),
                )
            except Exception:
                logger.exception("Unexpected error collecting approved APC command")
                return CliCollection(
                    runtime=evaluate_runtime_intent(
                        device_name,
                        None,
                        threshold_seconds,
                        warning_threshold_seconds,
                        source_command=command.value,
                        reason="Unexpected CLI collection error",
                    ),
                    commands_attempted=tuple(attempted),
                )

            try:
                measurement = parse_remaining_runtime(output)
            except RuntimeParseError as error:
                last_reason = str(error)
                if command is ReadOnlyCommand.RUNTIME:
                    logger.debug(
                        "Runtime absent from primary output; trying the fixed fallback command"
                    )
                    continue
                break
            return CliCollection(
                runtime=evaluate_runtime_intent(
                    device_name,
                    measurement.seconds,
                    threshold_seconds,
                    warning_threshold_seconds,
                    source_command=command.value,
                    raw_value=measurement.raw_value,
                ),
                commands_attempted=tuple(attempted),
            )

        all_unsupported = len(attempted) == 2 and unsupported_count == 2
        return CliCollection(
            runtime=evaluate_runtime_intent(
                device_name,
                None,
                threshold_seconds,
                warning_threshold_seconds,
                source_command=attempted[-1] if attempted else None,
                unavailable_status=RuntimeStatus.UNSUPPORTED
                if all_unsupported
                else RuntimeStatus.UNKNOWN,
                reason=last_reason,
            ),
            commands_attempted=tuple(attempted),
        )
