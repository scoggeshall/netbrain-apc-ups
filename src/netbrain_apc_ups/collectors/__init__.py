"""Safe collection interfaces."""

from netbrain_apc_ups.collectors.cli import (
    ALLOWED_COMMANDS,
    CliCollection,
    CliCollector,
    ReadOnlyCommand,
)

__all__ = [
    "ALLOWED_COMMANDS",
    "CliCollection",
    "CliCollector",
    "ReadOnlyCommand",
]
