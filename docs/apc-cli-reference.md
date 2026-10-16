# APC CLI reference status

This page records the present implementation boundary. The repository does
not yet contain verified vendor output examples or compatibility evidence for
the requested APC CLI command set. The command list and intended purposes are
tracked in the [safety matrix](command-safety-matrix.md). The runtime collector
uses its two fixed query names; the standalone SNMP verifier uses only `snmp`
and `snmpv3`.

The runtime parser recognizes a labeled field such as `Remaining Runtime:`
or `Runtime:` followed by `HH:MM:SS`, optional `N day HH:MM:SS`, or explicit
day/hour/minute/second units. These are tested using synthetic examples. They
must not be treated as an authoritative description of all NMC2/NMC3 firmware
output.

For each command enabled in the future, this reference must include a
vendor-documentation citation, purpose, output fields, supported model and
firmware, safety classification, automated-collection suitability, parser
behavior, and known limitations. Do not infer support from another card or UPS
model.

The SNMP profile parser is intentionally strict: it requires separately
identified user-profile and access-control tables and all fields for entries
1-4. It reports partial, truncated, or unrecognized output as unknown. The
repository checkout used to implement it did not include the referenced
`credentials.json`, `device_list.csv`, or incident log, so its checked-in
fixtures are sanitized format examples, not confirmed device captures. Confirm
them against sanitized NMC2/NMC3 outputs before relying on parser confidence.

The existing configuration script uses `-aN` for the authentication
passphrase and `-cN` for the privacy passphrase in SNMPv3 user-profile writes.
The supplied flag list identifies `-aN` but does not establish the `-cN`
privacy-passphrase flag. Accordingly, blank user profiles are not written
unless an operator explicitly confirms `-cN` in the target firmware's CLI help.
