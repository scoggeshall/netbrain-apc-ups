# APC CLI reference status

This page records the present implementation boundary. The repository does
not yet contain verified vendor output examples or compatibility evidence for
the requested APC CLI command set. The command list and intended purposes are
tracked in the [safety matrix](command-safety-matrix.md); only the two runtime
query names in that matrix are currently enabled.

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
