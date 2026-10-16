# Network Intents

## APC UPS Runtime - Minimum 60 Minutes

The implemented intent evaluates an estimated remaining-runtime measurement.
The default minimum is 3,600 seconds; equality passes. The threshold is
configurable per evaluation.

| Condition | Status |
|---|---|
| Runtime at or above the pass threshold | `PASS` |
| Runtime below the pass threshold | `FAIL` |
| Runtime between the pass and explicitly configured warning threshold | `WARN` |
| No valid measurement, parse failure, timeout, or connection failure | `UNKNOWN` |
| Both fixed runtime commands explicitly reported unsupported | `UNSUPPORTED` |

An optional warning threshold must be greater than or equal to the pass
threshold. It applies only above the pass threshold, so it cannot change the
default pass/fail outcome. Results include seconds, fractional minutes, raw
value, command, threshold, and status.

The parser is independent of the network transport. Synthetic fixtures cover
clock and explicit-unit examples. No sanitized real device capture has been
provided, so actual model/firmware output compatibility remains unverified.

Other monitoring intents described in the project proposal (availability,
operating status, load, battery, age, alarms, outlets, and self-test history)
are not implemented. No policy thresholds for those intents are asserted here.
