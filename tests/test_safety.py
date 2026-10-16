"""Synthetic tests that ensure collection cannot accept arbitrary commands."""

from netbrain_apc_ups.collectors.cli import (
    ALLOWED_COMMANDS,
    CliCollector,
    ReadOnlyCommand,
    UnsupportedCommandError,
)
from netbrain_apc_ups.intents.runtime import RuntimeStatus


class FakeTransport:
    def __init__(self, responses: dict[str, str | Exception]) -> None:
        self.responses = responses
        self.commands: list[str] = []

    def execute_read_only(self, command: str, timeout_seconds: float) -> str:
        self.commands.append(command)
        response = self.responses[command]
        if isinstance(response, Exception):
            raise response
        return response


def test_allowlist_contains_only_runtime_intent_commands() -> None:
    assert ALLOWED_COMMANDS == {ReadOnlyCommand.RUNTIME, ReadOnlyCommand.DETAILS}


def test_collector_uses_primary_runtime_command() -> None:
    transport = FakeTransport({"detstatus -rt": "Remaining Runtime: 01:00:00"})
    result = CliCollector(transport).collect_runtime("UPS-01")

    assert result.runtime.status is RuntimeStatus.PASS
    assert transport.commands == ["detstatus -rt"]


def test_unsupported_primary_uses_only_fixed_fallback() -> None:
    transport = FakeTransport(
        {
            "detstatus -rt": UnsupportedCommandError(),
            "detstatus -all": "Estimated Runtime: 00:55:00",
        }
    )
    result = CliCollector(transport).collect_runtime("UPS-01")

    assert result.runtime.status is RuntimeStatus.FAIL
    assert transport.commands == ["detstatus -rt", "detstatus -all"]
    assert result.commands_attempted == tuple(transport.commands)


def test_timeout_does_not_trigger_another_command() -> None:
    transport = FakeTransport({"detstatus -rt": TimeoutError()})
    result = CliCollector(transport).collect_runtime("UPS-01")

    assert result.runtime.status is RuntimeStatus.UNKNOWN
    assert transport.commands == ["detstatus -rt"]


def test_os_error_does_not_trigger_another_command() -> None:
    transport = FakeTransport({"detstatus -rt": OSError("connection refused")})
    result = CliCollector(transport).collect_runtime("UPS-01")

    assert result.runtime.status is RuntimeStatus.UNKNOWN
    assert transport.commands == ["detstatus -rt"]


def test_both_commands_unsupported_returns_unsupported() -> None:
    transport = FakeTransport(
        {
            "detstatus -rt": UnsupportedCommandError(),
            "detstatus -all": UnsupportedCommandError(),
        }
    )
    result = CliCollector(transport).collect_runtime("UPS-01")

    assert result.runtime.status is RuntimeStatus.UNSUPPORTED
    assert transport.commands == ["detstatus -rt", "detstatus -all"]
