# NetBrain APC UPS Monitoring Toolkit

This repository currently implements a read-only runtime-monitoring foundation
for APC UPS Network Management Cards. The parser and evaluator run independently
of live devices. No production connection or UPS operation is performed by the
tests.

## Implemented

- Python package installable from this repository.
- Parser for one labeled remaining-runtime value, including clock-style and
  explicit day/hour/minute/second formats.
- Runtime intent with configurable pass threshold (default 3,600 seconds) and
  optional warning threshold.
- Fixed-command CLI collector abstraction for `detstatus -rt`, with
  `detstatus -all` as a fallback. It accepts no caller-supplied command and
  performs no retries; a timeout stops collection.
- Synthetic unit tests and GitHub Actions test/lint workflow.

This is not yet a complete UPS monitoring toolkit. SSH connectivity, SNMPv3,
remaining metrics and intents, and NetBrain-specific execution/reporting have
not been implemented. See the [command safety matrix](docs/command-safety-matrix.md)
and [integration notes](docs/netbrain-integration.md) for limits and required
verification.

## Install and test

### Linux/macOS

```shell
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -q
ruff check src tests
ruff format --check src tests
```

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest -q
ruff check src tests
ruff format --check src tests
```

## Parse and evaluate

The following sample output is synthetic; it is not represented as an
APC-device capture:

```python
from netbrain_apc_ups import evaluate_runtime_intent, parse_remaining_runtime

measurement = parse_remaining_runtime("Remaining Runtime: 00:45:30")
result = evaluate_runtime_intent(
    device_name="UPS-HOSTNAME",
    runtime_seconds=measurement.seconds,
    raw_value=measurement.raw_value,
    source_command="detstatus -rt",
)
print(result.to_dict())
```

The default threshold is 3,600 seconds. Runtime exactly at or above the
threshold passes. An optional `warning_threshold_seconds` must be at least the
pass threshold; it warns only in the range from the pass threshold up to (but
not including) that warning threshold. It cannot mask a failing runtime.
Missing measurements are `UNKNOWN`; confirmed unsupported measurements are
`UNSUPPORTED`.

Parser-supported formats are based on synthetic test cases and require
confirmation against sanitized NMC2/NMC3 device captures before production use.
Ambiguous, unitless, malformed, and duplicate runtime values are rejected.

## Safety

The collector has a central allowlist of two fixed query commands. This
implementation does not include SSH credentials or a live SSH/SNMP transport.
It does not provide a generic command execution interface. No shutdown, outlet
switch, reboot, self-test, calibration, configuration, firmware, reset, or
SNMP SET operation is implemented.

Do not enable additional commands until their behavior and read-only
classification have been checked against authoritative APC/Schneider Electric
documentation for the target card and firmware. No live device testing has
been performed.

## Project status and references

The runtime parser/evaluator and safety behavior have synthetic unit tests.
There has been no device, NetBrain, SNMP, or integration testing. The vendor
documentation needed to substantiate command/firmware compatibility and
PowerNet MIB mappings could not be verified in this environment; those
compatibility claims are intentionally left open rather than inferred.

- [CLI command safety and compatibility](docs/command-safety-matrix.md)
- [Runtime Network Intent](docs/network-intents.md)
- [NetBrain integration requirements](docs/netbrain-integration.md)
- [APC CLI reference status](docs/apc-cli-reference.md)
