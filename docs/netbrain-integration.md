# NetBrain integration status

NetBrain 12.3.1.2-specific execution, parser, adapter, or SDK support has not
been verified or implemented. The repository therefore makes no claims about
which Network Intent mechanisms, CLI execution features, or APIs are available
in that release.

The current Python code provides an independent parser, runtime evaluator, and
transport protocol. An integration can pass captured CLI output to the parser
and publish `RuntimeIntentResult.to_dict()` if the target NetBrain mechanism
supports an external collector or equivalent approved workflow. Do not treat
this as a verified NetBrain configuration recipe.

Confirm these points with the NetBrain 12.3.1.2 administrator or representative
before designing an adapter:

1. Which supported Network Intent mechanism can execute an approved SSH CLI
   command against an APC NMC?
2. Whether APC NMC devices are supported targets for that execution method.
3. How command output and execution errors/timeouts are captured and exposed.
4. Whether an external Python collector is permitted and how it can securely
   authenticate.
5. How numeric measurements, `UNKNOWN`, `UNSUPPORTED`, and original raw
   measurements should be represented in results.
6. Which network/device credentials and trust boundaries apply.

No credentials, production endpoints, or live NetBrain APIs are included.
Parser tests do not require NetBrain.
