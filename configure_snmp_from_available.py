#!/usr/bin/env python3
"""Add an SNMPv3 profile only when its documented default slot is unused.

This utility is intentionally conservative. It reads ``snmpv3`` configuration
over SSH and only writes a profile whose username is still the APC default,
whose authentication and privacy protocols are ``none``, and whose matching
access-control entry is explicitly disabled. Unknown output or any occupied
slot is skipped. It never toggles global SNMP settings or changes SNMPv1.

The readback labels below follow Schneider Electric's NMC2 User Guide. Other
firmware output formats are treated as unknown and must be verified before
adding a parser for them.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import paramiko
except ImportError:  # pragma: no cover - exercised in CLI environment
    paramiko = None  # type: ignore[assignment]


DEFAULT_USER = "apc snmp profile{slot}"
PROMPT = re.compile(r"(?m)apc>\s*$", re.IGNORECASE)
SENSITIVE_FLAG = re.compile(r'(?i)(\s-(?:a|c)\d?\s+)(?:"[^"]*"|\S+)')


@dataclass(frozen=True)
class SlotState:
    slot: int
    username: str | None
    auth_protocol: str | None
    privacy_protocol: str | None
    access_username: str | None
    access: str | None

    @property
    def available(self) -> bool:
        return (
            self.username == DEFAULT_USER.format(slot=self.slot)
            and self.auth_protocol == "none"
            and self.privacy_protocol == "none"
            and self.access_username == DEFAULT_USER.format(slot=self.slot)
            and self.access == "disabled"
        )


def parse_slot_states(readback: str) -> dict[int, SlotState]:
    """Parse documented NMC2 status labels; omit slots that are ambiguous."""
    profiles: dict[int, dict[str, str]] = {}
    current_slot: int | None = None
    section = ""
    for line in readback.splitlines():
        line = line.strip()
        if re.search(r"SNMPv3\s+User\s+Profiles?", line, re.IGNORECASE):
            section = "profiles"
            current_slot = None
            continue
        if re.search(r"SNMPv3\s+Access\s+Control", line, re.IGNORECASE):
            section = "access"
            current_slot = None
            continue
        profile_match = re.search(
            r"^(?:user\s+profile|profile)\s*(\d)\s*:?\s*(.*)$", line, re.IGNORECASE
        )
        if profile_match and 1 <= int(profile_match.group(1)) <= 4:
            current_slot = int(profile_match.group(1))
            profiles.setdefault(current_slot, {})
            remainder = profile_match.group(2).strip()
            if remainder:
                profiles[current_slot]["username"] = remainder
            continue
        index_match = re.search(r"(?:access\s+control\s+)?index\s*:\s*(\d)", line, re.IGNORECASE)
        if index_match and 1 <= int(index_match.group(1)) <= 4:
            current_slot = int(index_match.group(1))
            if section == "profiles":
                profiles.setdefault(current_slot, {})
            continue
        if current_slot is not None:
            for key, pattern in (
                ("username", r"(?:user\s*name|name)\s*:\s*(.+)$"),
                ("auth_protocol", r"(?:authentication\s+protocol|auth\s+protocol)\s*:\s*(\S+)"),
                ("privacy_protocol", r"(?:privacy|encryption)\s+protocol\s*:\s*(\S+)"),
            ):
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    profiles[current_slot][key] = (
                        match.group(1).strip().lower()
                        if key != "username"
                        else match.group(1).strip()
                    )

    access_entries: dict[int, dict[str, str]] = {}
    current_entry: int | None = None
    for line in readback.splitlines():
        line = line.strip()
        index_match = re.search(r"(?:access\s+control\s+)?index\s*:\s*(\d)", line, re.IGNORECASE)
        if index_match and 1 <= int(index_match.group(1)) <= 4:
            current_entry = int(index_match.group(1))
            access_entries.setdefault(current_entry, {})
            continue
        if current_entry is not None:
            user_match = re.search(r"user\s*name\s*:\s*(.+)$", line, re.IGNORECASE)
            if user_match:
                access_entries[current_entry]["username"] = user_match.group(1).strip()
            access_match = re.search(r"access\s*:\s*(enabled|disabled)", line, re.IGNORECASE)
            if access_match:
                access_entries[current_entry]["access"] = access_match.group(1).lower()

    states: dict[int, SlotState] = {}
    for slot in range(1, 5):
        profile = profiles.get(slot, {})
        access = access_entries.get(slot, {}).get("access")
        # Include only complete slots so missing or unfamiliar data cannot be
        # mistaken for availability.
        access_username = access_entries.get(slot, {}).get("username")
        if (
            all(k in profile for k in ("username", "auth_protocol", "privacy_protocol"))
            and access_username
            and access
        ):
            states[slot] = SlotState(
                slot=slot,
                username=profile["username"],
                auth_protocol=profile["auth_protocol"],
                privacy_protocol=profile["privacy_protocol"],
                access_username=access_username,
                access=access,
            )
    return states


def choose_available_slot(readback: str) -> int | None:
    """Return the lowest explicitly unused slot, else None."""
    states = parse_slot_states(readback)
    return next((slot for slot in sorted(states) if states[slot].available), None)


def build_profile_commands(slot: int, config: dict[str, Any]) -> list[str]:
    """Build only the two SNMPv3 changes for a checked free slot."""
    if slot not in range(1, 5):
        raise ValueError("slot must be between 1 and 4")
    username = str(config.get("username", "")).strip()
    nms_ip = str(config.get("nms_ip", "")).strip()
    auth = str(config.get("auth_passphrase", ""))
    privacy = str(config.get("privacy_passphrase", ""))
    if not all((username, nms_ip, auth, privacy)):
        raise ValueError("username, nms_ip, auth_passphrase, and privacy_passphrase are required")
    if (
        '"' in username
        or '"' in auth
        or '"' in privacy
        or any(c in username + auth + privacy for c in "\r\n")
    ):
        raise ValueError("credential values cannot contain quotes or line breaks")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", nms_ip):
        raise ValueError("nms_ip must be an IP address or hostname without shell characters")
    return [
        f'snmpv3 -u{slot} "{username}" -ap{slot} sha -pp{slot} aes -a{slot} "{auth}" -c{slot} "{privacy}"',
        f'snmpv3 -ac{slot} enable -au{slot} "{username}" -n{slot} {nms_ip}',
    ]


def run_command(shell: Any, command: str, timeout: float = 15.0) -> str:
    if shell.recv_ready():
        shell.recv(65535)
    shell.send(command + "\r\n")
    output = ""
    deadline = time.monotonic() + timeout
    last_received: float | None = None
    while time.monotonic() < deadline:
        if shell.recv_ready():
            output += shell.recv(65535).decode("utf-8", errors="replace")
            last_received = time.monotonic()
            if PROMPT.search(output):
                return output
        elif last_received is not None and time.monotonic() - last_received > 1.0:
            break
        else:
            time.sleep(0.1)
    raise TimeoutError(f"Timed out waiting for response to {command.split()[0]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="NMC hostname or IP; no default device is configured")
    parser.add_argument("--credentials", type=Path, default=Path("snmpv3_add_credentials.json"))
    parser.add_argument("--ssh-username", required=True)
    args = parser.parse_args()
    if paramiko is None:
        print("Install Paramiko with: python -m pip install paramiko", file=sys.stderr)
        return 2
    try:
        config = json.loads(args.credentials.read_text(encoding="utf-8"))
        ssh_password = config.pop("ssh_password")
        commands = build_profile_commands(1, config)  # Slot is re-selected after live readback.
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            args.host,
            username=args.ssh_username,
            password=ssh_password,
            timeout=15,
            banner_timeout=15,
            auth_timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
        shell = client.invoke_shell(width=160, height=40)
        time.sleep(0.3)
        if shell.recv_ready():
            shell.recv(65535)
        readback = run_command(shell, "snmpv3")
        slot = choose_available_slot(readback)
        if slot is None:
            print("No explicitly unused SNMPv3 slot found; no configuration changes made.")
            return 1
        commands = build_profile_commands(slot, config)
        print(f"Explicit default slot {slot} is unused; applying SNMPv3 profile and access entry.")
        for command in commands:
            response = run_command(shell, command)
            if not re.search(r"\bE000:\s*Success\b", response, re.IGNORECASE):
                safe_response = SENSITIVE_FLAG.sub(r"\1<REDACTED>", response)
                print(
                    f"Command not confirmed; stopping. Response: {safe_response}", file=sys.stderr
                )
                return 1
        print(f"Profile {slot} commands accepted. Verify through the NMC UI/readback before use.")
        return 0
    except (
        OSError,
        TimeoutError,
        ValueError,
        paramiko.SSHException,
    ) as exc:  # no credentials in errors
        print(f"Operation stopped safely: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
