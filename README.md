# NetBrain APC UPS Monitoring Toolkit

A production-ready Python toolkit for collecting, parsing, and evaluating APC/Schneider Electric UPS information for use with NetBrain Network Intent.

## Objective

This project provides safe, modular monitoring of APC Smart-UPS and Smart-UPS RT/SRT systems via SSH CLI and optional SNMPv3. It enables NetBrain to track UPS health, remaining runtime, power consumption, battery status, and alarms without ever executing power-control operations.

**Critical Production Requirement:** This toolkit is strictly read-only. It will never shut down, reboot, cycle, or interrupt a UPS, outlet, battery system, or connected network equipment.

## Supported Platforms

- **APC Smart-UPS** and **Smart-UPS RT/SRT** systems
- **NMC2** (Network Management Card 2) including AP9630
- **NMC3** (Network Management Card 3) including AP9640
- Various UPS models: SMT1500, SMT1500C, Smart-UPS 3000/5000/750, SRT systems
- **NetBrain** 12.3.1.2
- SSH-based CLI access with SNMPv3 as optional supplement

## Architecture

```
src/netbrain_apc_ups/
├── models/               # Dataclasses and typed structures
├── collectors/           # SSH CLI and SNMP data collection
├── parsers/              # Raw output parsing and normalization
├── intents/              # Network Intent evaluators
└── adapters/             # NetBrain integration layer
```

### Design Principles

1. **Modular separation** — Connection, collection, parsing, evaluation, and reporting are independently testable
2. **Defensive parsing** — Handles missing values, unsupported commands, and firmware variations
3. **Configurable thresholds** — No hardcoded device-specific values
4. **Explicit allowlisting** — Only documented read-only commands are executed
5. **Type safety** — Full type hints and dataclass models
6. **Production logging** — Structured logging for troubleshooting without exposing credentials

## Initial Network Intent: APC UPS Runtime ≥ 60 Minutes

The first functional requirement evaluates whether an APC UPS has at least 60 minutes of estimated remaining battery runtime.

**Runtime Status Evaluation:**
- `PASS` — Runtime ≥ 60 minutes
- `FAIL` — Runtime < 60 minutes
- `UNKNOWN` — Runtime unavailable, invalid, or unsupported

**Example output:**
```json
{
  "device": "UPS-HOSTNAME",
  "metric": "remaining_runtime",
  "runtime_seconds": 2700,
  "runtime_minutes": 45,
  "threshold_minutes": 60,
  "status": "FAIL",
  "source_command": "detstatus -rt"
}
```

## Supported APC CLI Commands (Read-Only)

| Command | Purpose | NMC2 | NMC3 | Output | Read-Only |
|---------|---------|------|------|--------|-----------|
| `detstatus -rt` | Remaining runtime | ✓ | ✓ | Structured | Yes |
| `detstatus -all` | All device details | ✓ | ✓ | Structured | Yes |
| `ups -st` | UPS status | ✓ | ✓ | Structured | Yes |
| `ups -os` | Output status | ✓ | ✓ | Structured | Yes |
| `upsabout` | UPS identification | ✓ | ✓ | Structured | Yes |
| `detstatus -om` | Output measurements | ✓ | ✓ | Structured | Yes |
| `detstatus -soc` | State of charge | ✓ | ✓ | Structured | Yes |
| `detstatus -bat` | Battery status | ✓ | ✓ | Structured | Yes |
| `detstatus -dg` | Diagnostics | ✓ | ✓ | Structured | Yes |
| `detbat -all` | Battery details | ✓ | ✓ | Structured | Yes (optional) |

**Not supported (power-control operations):**
- `cfgshutdn` — Shutdown configuration
- `cfgpower` — Outlet control
- Self-test initiation
- Firmware updates
- Factory resets
- Any command that modifies device state

## Installation

### Development

```bash
git clone https://github.com/scoggeshall/netbrain-apc-ups.git
cd netbrain-apc-ups
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev,test]"
```

### Testing

```bash
pytest tests/ -v
```

### Linting and Formatting

```bash
ruff check src/ tests/
ruff format src/ tests/
```

## Quick Start

### Parse Remaining Runtime

```python
from netbrain_apc_ups.parsers.runtime import parse_remaining_runtime

cli_output = """
Remaining Runtime:     00:45:30

"""

runtime = parse_remaining_runtime(cli_output)
print(f"Runtime: {runtime.minutes} minutes ({runtime.seconds} seconds)")
# Output: Runtime: 45 minutes (2730 seconds)
```

### Evaluate Runtime Intent

```python
from netbrain_apc_ups.intents.runtime import evaluate_runtime_intent

result = evaluate_runtime_intent(
    device_name="UPS-01",
    runtime_seconds=2730,
    threshold_minutes=60
)
print(result)
# {
#   "device": "UPS-01",
#   "metric": "remaining_runtime",
#   "runtime_seconds": 2730,
#   "runtime_minutes": 45.5,
#   "threshold_minutes": 60,
#   "status": "FAIL",
#   "source_command": "detstatus -rt"
# }
```

## Safety and Compliance

### Read-Only Operations Only

All commands are strictly read-only. The codebase includes:
- Explicit command allowlist
- No shutdown/reboot/outlet control methods
- No configuration change functions
- No power-cycle operations
- No self-test initiation
- No firmware update mechanisms

### Credential Management

- No plaintext credentials in code
- SSH key authentication preferred
- Environment variable or secure vault integration
- No default passwords

### Error Handling

- Timeout handling for slow or unreachable devices
- Graceful degradation when commands are unsupported
- Distinguishes between "unavailable" and "failed"
- Never assumes missing data means healthy status

## NetBrain Integration

NetBrain can use this toolkit by:
1. Executing read-only APC CLI commands via SSH
2. Capturing raw output
3. Parsing output using the `parsers` module
4. Evaluating using Network Intent evaluators in `intents`
5. Reporting structured results as JSON

See `docs/netbrain-integration.md` for detailed integration steps.

## Development Phases

1. **Phase 1** — Repository foundation ✓
2. **Phase 2** — APC CLI command documentation
3. **Phase 3** — Runtime parser implementation
4. **Phase 4** — First Network Intent evaluator
5. **Phase 5** — NetBrain integration specifications
6. **Phase 6** — Automated testing and validation

## Documentation

- `docs/apc-cli-commands.md` — Complete APC command reference and support matrix
- `docs/netbrain-integration.md` — NetBrain 12.3.1.2 integration guide
- `docs/parser-specifications.md` — Parser input/output formats
- `examples/` — Sample synthetic APC CLI outputs and configurations

## Contributing

All contributions must:
- Include unit tests with synthetic fixtures
- Pass `ruff` linting and formatting
- Never connect to production UPS equipment without authorization
- Document any firmware-specific variations
- Verify read-only operation before committing

## License

MIT License — See LICENSE file

## Support and Issues

For issues, feature requests, or safety concerns:
1. Create a GitHub issue with reproduction steps
2. Include sanitized CLI output if applicable
3. Never include credentials or device IP addresses
4. Reference the APC command and NMC model/firmware

---

**Status:** Phase 1 Complete — Repository foundation initialized. Ready for Phase 2 (Command documentation) and Phase 3 (Parser implementation).
