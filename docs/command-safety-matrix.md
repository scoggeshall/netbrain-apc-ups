# APC CLI command safety and compatibility

This matrix distinguishes command names requested for investigation from
commands currently enabled for automated collection. Vendor documentation was
not reachable during this implementation, so names/purposes below are not
claims of verified model or firmware compatibility. Consult the cited
Schneider Electric/APC documentation for the exact UPS, NMC model, and firmware
before enabling commands beyond the fixed runtime allowlist.

| Command | Intended data | Automated status | Safety / compatibility evidence |
|---|---|---|---|
| `detstatus -rt` | Remaining runtime | Enabled; primary runtime collection | Read-only query by intended use; vendor compatibility not yet independently verified |
| `detstatus -all` | Device status/details, including runtime when exposed | Enabled; fixed fallback only | Read-only query by intended use; output varies and compatibility not yet verified |
| `ups -st` | UPS status | Disabled | Not verified |
| `ups -os` | Output status | Disabled | Not verified |
| `upsabout` | UPS identity/information | Disabled | Not verified |
| `detstatus -om` | Output measurements | Disabled | Not verified |
| `detstatus -soc` | State of charge | Disabled | Not verified |
| `detstatus -bat` | Battery status/details | Disabled | Not verified |
| `detstatus -dg` | Diagnostic information | Disabled | Not verified |
| `detbat -all` | Battery details | Disabled; may be unsupported | Compatibility varies by model/firmware; gracefully handle only after a verified safe collector is added |
| `alarmcount` | Alarm counts | Disabled | Not verified |
| `cfgshutdn -all` | Shutdown configuration | Rejected; not in allowlist | Must not be enabled without authoritative proof that invocation is strictly read-only |
| `cfgpower -all` | Power/outlet configuration | Rejected; not in allowlist | Must not be enabled without authoritative proof that invocation is strictly read-only |
| `about` | NMC/system information | Disabled | Not verified |
| `eventlog` | Event history | Excluded from automation | Potentially interactive; use manual troubleshooting only unless a safe noninteractive retrieval method is verified |

The allowlist in `src/netbrain_apc_ups/collectors/cli.py` includes only
`detstatus -rt` and `detstatus -all`. Collection uses these exact commands,
with no user-provided command string. A transport timeout or connection failure
stops collection without retrying. A fallback is attempted only after the
primary command is explicitly unsupported or its output cannot be parsed; the
fallback is itself fixed and allowlisted.

## Verification sources required

No authoritative command reference was confirmed during this task. Before
expanding support, consult current Schneider Electric/APC documentation for the
specific NMC2/NMC3 and firmware, including command syntax, output examples,
interactivity, and whether invoking the command can modify device state.
Document source titles, URLs/document identifiers, and applicable firmware
versions here after verification. The runtime examples in tests are synthetic,
not device captures.
