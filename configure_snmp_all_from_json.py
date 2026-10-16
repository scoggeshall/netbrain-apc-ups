#!/usr/bin/env python3
"""
Configure APC NMC SNMPv1 and SNMPv3 settings from credentials.json.

Safety behavior:
- Only configures numbered entries for which the corresponding JSON values exist.
- Does not clear/reset entries omitted from JSON.
- Does not reboot devices.
- Logs command results with passphrases/community strings masked.
- Test on one UPS before using against the full device list.

Requires: paramiko (py -m pip install paramiko)

Expected files beside this script:
  credentials.json
  device_list.csv  (header: IP)

JSON keys supported:
  ssh_username, ssh_password, optional alt_username, alt_password
  snmpv1_nms_ip, snmpv1_community_1, snmpv1_community_2, snmpv1_community_3
  snmpv1_access_1, snmpv1_access_2, snmpv1_access_3 (optional; default "read")
  snmpv3_username, snmpv3_nms_ip_1, snmpv3_nms_ip_2,
  snmpv3_auth_passphrase, snmpv3_privacy_passphrase
  snmpv3_profile2_username, snmpv3_profile2_nms_ip,
  snmpv3_profile2_auth_passphrase, snmpv3_profile2_privacy_passphrase
  Optional profiles 3 and 4 follow the same naming pattern:
  snmpv3_profile3_username, snmpv3_profile3_nms_ip,
  snmpv3_profile3_auth_passphrase, snmpv3_profile3_privacy_passphrase
  snmpv3_profile4_username, snmpv3_profile4_nms_ip,
  snmpv3_profile4_auth_passphrase, snmpv3_profile4_privacy_passphrase

SNMPv3 profile N is paired with access-control entry N. Profile 1 can also
use access entries 1 and 2 via snmpv3_nms_ip_1 / snmpv3_nms_ip_2; this
supports two managers for the first user profile. For profiles 2-4, the
single *_nms_ip value is applied to the matching access entry.
"""
import csv
import json
import logging
import re
import sys
import time
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("Missing dependency. Install with: py -m pip install paramiko")
    raise SystemExit(2)

BASE = Path(__file__).resolve().parent
CREDENTIALS_FILE = BASE / "credentials.json"
DEVICE_FILE = BASE / "device_list.csv"
LOG_DIR = BASE / "Log"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / f"configure_snmp_all_{time.strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("apc-snmp")

SECRET_KEYS = ("passphrase", "community", "password", " -a", " -c")


def mask_command(command: str) -> str:
    # Mask values following secret-bearing CLI flags.
    return re.sub(r'(?i)(\s-(?:a|c)\d?\s+)(?:"[^"]*"|\S+)', r'\1<REDACTED>', command)


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("credentials.json must contain a JSON object")
    return data


def required_credentials(c: dict):
    missing = [k for k in ("ssh_username", "ssh_password") if not c.get(k)]
    if missing:
        raise ValueError("Missing required credentials.json key(s): " + ", ".join(missing))


def read_devices(path: Path):
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    if not rows or "IP" not in rows[0]:
        raise ValueError("device_list.csv must contain an 'IP' header and at least one device")
    return [r["IP"].strip() for r in rows if r.get("IP", "").strip()]


def build_commands(c: dict):
    commands = []

    # SNMPv1: configure only entries whose community is populated.
    v1_ip = str(c.get("snmpv1_nms_ip", "")).strip()
    for n in range(1, 4):
        community = str(c.get(f"snmpv1_community_{n}", "")).strip()
        if community and v1_ip:
            access = str(c.get(f"snmpv1_access_{n}", "read")).strip().lower()
            if access not in {"read", "write", "writeplus", "disable"}:
                raise ValueError(f"Invalid snmpv1_access_{n}: {access}")
            commands.append((
                f"Configure SNMPv1 access entry {n}",
                f'snmp -c{n} "{community}" -a{n} {access} -n{n} {v1_ip}',
                True,
            ))

    # SNMPv3 global enable is only sent if explicitly requested, otherwise
    # preserve the device's current global setting.
    if c.get("snmpv3_enable") is True or str(c.get("snmpv3_enable", "")).lower() in {"true", "yes", "enable", "enabled", "1"}:
        commands.append(("Enable SNMPv3 globally", "snmpv3 -S enable", False))
    elif c.get("snmpv3_enable") is False or str(c.get("snmpv3_enable", "")).lower() in {"false", "no", "disable", "disabled", "0"}:
        commands.append(("Disable SNMPv3 globally", "snmpv3 -S disable", False))

    # Profile 1 uses the original keys.
    profile_specs = [{
        "n": 1,
        "username": c.get("snmpv3_username"),
        "auth": c.get("snmpv3_auth_passphrase"),
        "privacy": c.get("snmpv3_privacy_passphrase"),
        "nms": [],
    }]
    for key, entry in (("snmpv3_nms_ip_1", 1), ("snmpv3_nms_ip_2", 2)):
        ip = str(c.get(key, "")).strip()
        if ip:
            profile_specs[0]["nms"].append((entry, ip))

    # Optional profile 2-4. Only complete profiles are configured.
    for n in range(2, 5):
        profile_specs.append({
            "n": n,
            "username": c.get(f"snmpv3_profile{n}_username"),
            "auth": c.get(f"snmpv3_profile{n}_auth_passphrase"),
            "privacy": c.get(f"snmpv3_profile{n}_privacy_passphrase"),
            "nms": [],
        })
        ip = str(c.get(f"snmpv3_profile{n}_nms_ip", "")).strip()
        if ip:
            profile_specs[-1]["nms"].append((n, ip))

    for spec in profile_specs:
        n = spec["n"]
        username = str(spec["username"] or "").strip()
        auth = str(spec["auth"] or "").strip()
        privacy = str(spec["privacy"] or "").strip()
        if username and auth and privacy:
            commands.append((
                f"Configure SNMPv3 user profile {n}",
                f'snmpv3 -u{n} "{username}" -ap{n} sha -pp{n} aes -a{n} "{auth}" -c{n} "{privacy}"',
                True,
            ))
        elif username or auth or privacy:
            log.warning("Profile %s has incomplete JSON fields; skipping user-profile command.", n)

        # Apply only the access entries that have a manager IP and username.
        if username:
            for entry, ip in spec["nms"]:
                commands.append((
                    f"Configure SNMPv3 access-control entry {entry} for profile {n}",
                    f'snmpv3 -ac{entry} enable -au{entry} "{username}" -n{entry} {ip}',
                    False,
                ))
    return commands


def connect(host: str, c: dict):
    attempts = [
        (c["ssh_username"], c["ssh_password"]),
        (c.get("alt_username"), c.get("alt_password")),
    ]
    last_error = None
    for username, password in attempts:
        if not username or not password:
            continue
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host, username=username, password=password,
                timeout=15, banner_timeout=15, auth_timeout=15,
                look_for_keys=False, allow_agent=False,
            )
            return client
        except Exception as exc:
            last_error = exc
            client.close()
    raise RuntimeError(f"SSH connection failed: {last_error}")


def run_command(shell, command: str, timeout: int = 15) -> str:
    # Clear any pending prompt/output before issuing the next command.
    if shell.recv_ready():
        try:
            shell.recv(65535)
        except Exception:
            pass
    shell.send(command + "\r\n")
    output = ""
    deadline = time.time() + timeout
    quiet_since = None
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            quiet_since = time.time()
            if re.search(r"(?m)apc>\s*$", output):
                break
        else:
            if quiet_since and time.time() - quiet_since > 1.0:
                break
            time.sleep(0.15)
    return output.strip()


def response_ok(output: str) -> bool:
    # Accept explicit APC success, or a nonempty response without a known
    # APC error code. Verification is still separately logged as readback.
    if re.search(r"\bE000:\s*Success\b", output, re.I):
        return True
    if re.search(r"\bE00[1-9]:", output, re.I):
        return False
    return bool(output.strip()) and not re.search(r"\b(?:invalid command|syntax error|error:)\b", output, re.I)


def configure_device(host: str, c: dict, commands):
    client = None
    try:
        client = connect(host, c)
        shell = client.invoke_shell(width=180, height=50)
        time.sleep(0.5)
        if shell.recv_ready():
            shell.recv(65535)
        log.info("[%s] Connected over SSH.", host)
        outcomes = []
        for label, command, secret in commands:
            shown = mask_command(command) if secret else command
            log.info("[%s] %s: %s", host, label, shown)
            output = run_command(shell, command)
            ok = response_ok(output)
            # Redact returned command echo if it contains secrets.
            safe_output = output
            if secret:
                for key in ("snmpv1_community_1", "snmpv1_community_2", "snmpv1_community_3",
                            "snmpv3_auth_passphrase", "snmpv3_privacy_passphrase",
                            "snmpv3_profile2_auth_passphrase", "snmpv3_profile2_privacy_passphrase",
                            "snmpv3_profile3_auth_passphrase", "snmpv3_profile3_privacy_passphrase",
                            "snmpv3_profile4_auth_passphrase", "snmpv3_profile4_privacy_passphrase"):
                    value = str(c.get(key, ""))
                    if value:
                        safe_output = safe_output.replace(value, "<REDACTED>")
            log.info("[%s] %s: %s | response=%s", host, "Success" if ok else "Unconfirmed",
                     label, safe_output.replace("\n", " | ")[:1600])
            outcomes.append(ok)

        # Read-only diagnostics; do not use assumed text format as definitive verification.
        readback = run_command(shell, "snmp")
        log.info("[%s] SNMP readback: %s", host, readback.replace("\n", " | ")[:3000])
        readback3 = run_command(shell, "snmpv3")
        log.info("[%s] SNMPv3 readback: %s", host, readback3.replace("\n", " | ")[:5000])
        if not commands:
            return host, "NO CHANGES (no applicable SNMP keys in JSON)"
        return host, "COMMANDS ACCEPTED" if all(outcomes) else "PARTIAL (inspect log/readback)"
    except Exception as exc:
        log.exception("[%s] Device configuration failed: %s", host, exc)
        return host, f"FAILED: {exc}"
    finally:
        if client:
            client.close()


def main():
    try:
        c = read_json(CREDENTIALS_FILE)
        required_credentials(c)
        devices = read_devices(DEVICE_FILE)
        commands = build_commands(c)
    except Exception as exc:
        print(f"Setup error: {exc}")
        raise SystemExit(2)

    if not commands:
        print("No SNMP settings to apply. Check credentials.json keys.")
        raise SystemExit(2)

    print(f"Devices: {len(devices)} | Commands per device: {len(commands)}")
    print(f"Log: {LOG_FILE}")
    print("WARNING: This configures every SNMP entry represented by populated JSON keys.")
    print("No omitted entry is cleared, and no device is rebooted.")
    for host in devices:
        device, status = configure_device(host, c, commands)
        print(f"[{device}] {status}")


if __name__ == "__main__":
    main()
