# NetBrain APC UPS Monitoring Toolkit

This repository implements a read-only runtime-monitoring foundation and a
standalone read-only SNMP-profile verifier for APC UPS Network Management Cards.
The parser and evaluator run independently of live devices. Tests use local
fixtures and never connect to or modify UPS devices.

## Implemented

- Python package installable from this repository.
- Parser for one labeled remaining-runtime value, including clock-style and
  explicit day/hour/minute/second formats.
- Runtime intent with configurable pass threshold (default 3,600 seconds) and
  optional warning threshold.
- Fixed-command CLI collector abstraction for `detstatus -rt`, with
  `detstatus -all` as a fallback. It accepts no caller-supplied command and
  performs no retries; a timeout stops collection.
- Standalone SNMP profile verifier that issues only `snmp` and `snmpv3` read
  commands and exports parsed per-entry results to CSV.
- Synthetic unit tests and GitHub Actions test/lint workflow.

This is not yet a complete UPS monitoring toolkit. SNMP profile configuration
remains a separate legacy script and is guarded by explicit write scope; it is
not part of the package runtime collector. See the [command safety
matrix](docs/command-safety-matrix.md), [APC CLI reference
status](docs/apc-cli-reference.md), and [integration
notes](docs/netbrain-integration.md) for limits and required verification.

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

## Read-only SNMP profile verification

The standalone `verify_apc_snmp_profiles.py` script reads the existing
`credentials.json` and `device_list.csv` files. It requires Paramiko and a
trusted host key in the user's SSH `known_hosts` file (or the configured
`ssh.known_hosts` file). It sends only `snmp` and `snmpv3`, does not alter global
SNMP settings, and never reboots a device.

Run it from the repository directory against one allowlisted device:

```powershell
py .\verify_apc_snmp_profiles.py --host 10.0.0.1
py .\configure_snmp_blank_profiles_only_verified_workers.py --host 10.0.0.1 --dry-run
```

Replace `10.0.0.1` in both commands with the same explicitly approved IP present
in `device_list.csv`. The verifier writes a timestamped CSV and log under
`Log\`. Community strings are redacted; SNMPv3 passphrases are not readable
from the CLI and are marked accordingly. Unrecognized, incomplete, or partial
output is `UNKNOWN`, not a blank profile.

The configuration script does not write unless `--write` is supplied. A write
requires `--host` for one device. Broader writes additionally require an
all-`VERIFIED` CSV from the verifier, `--report-reviewed`, and
`--allow-broader-run`. SNMPv3 user-profile writes are withheld unless
`--confirm-v3-privacy-flag-c` is supplied after confirming that the target
firmware's CLI help documents the existing `-cN` privacy-passphrase flag. Do
not confirm that syntax based only on another firmware's help.

## Safety

The runtime package collector has a central allowlist of two fixed query
commands. It does not include SSH credentials or a live transport. The
standalone verifier uses SSH only when explicitly run and has a separate fixed
read-only command list. Neither program provides a generic command execution
interface. No shutdown, outlet switch, reboot, self-test, calibration,
firmware, reset, or global SNMP/SNMPv3 setting command is implemented.

Do not enable additional commands until their behavior and read-only
classification have been checked against authoritative APC/Schneider Electric
documentation for the target card and firmware. No live device testing has
been performed.

## Project status and references

The runtime parser/evaluator and SNMP profile parsers have local fixture tests.
There has been no device, NetBrain, SNMP, or integration testing. The vendor
documentation needed to substantiate command/firmware compatibility and
PowerNet MIB mappings could not be verified in this environment; those
compatibility claims are intentionally left open rather than inferred.

- [CLI command safety and compatibility](docs/command-safety-matrix.md)
- [Runtime Network Intent](docs/network-intents.md)
- [NetBrain integration requirements](docs/netbrain-integration.md)
- [APC CLI reference status](docs/apc-cli-reference.md)
