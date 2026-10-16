"""Read-only APC UPS monitoring primitives."""

from netbrain_apc_ups.intents.runtime import RuntimeStatus, evaluate_runtime_intent
from netbrain_apc_ups.parsers.runtime import RuntimeMeasurement, parse_remaining_runtime

__all__ = [
    "RuntimeMeasurement",
    "RuntimeStatus",
    "evaluate_runtime_intent",
    "parse_remaining_runtime",
]
