"""Safe collection interfaces."""

from netbrain_apc_ups.collectors.cli import (
    ALLOWED_COMMANDS,
    CliCollection,
    CliCollector,
    CommandResult,
    CommandStatus,
    ReadOnlyCommand,
)

__all__ = [
    "ALLOWED_COMMANDS",
    "CliCollection",
    "CliCollector",
    "CommandResult",
    "CommandStatus",
    "ReadOnlyCommand",
]
