#!/usr/bin/env python3
"""Configure up to four independent APC NMC SNMPv1 and SNMPv3 entries from JSON.

Expected beside this script:
  credentials.json
  device_list.csv (header: IP)

Install dependency:
  py -m pip install paramiko

JSON structure:
{
  "ssh": {"username": "...", "password": "...", "alt_username": "", "alt_password": ""},
  "snmpv1": {
    "profile1": {"enabled": true, "nms_ip": "...", "community": "...", "access": "read"},
    ...
    "profile4": {"enabled": true, "nms_ip": "...", "community": "...", "access": "read"}
  },
  "snmpv3": {
    "enabled": true,
    "profile1": {"enabled": true, "username": "...", "nms_ip": "...", "auth_passphrase": "...", "privacy_passphrase": "...", "auth_protocol": "sha", "privacy_protocol": "aes"},
    ...
    "profile4": {...}
  }
}

Each SNMPv1 profile maps to SNMPv1 access entry N.
Each SNMPv3 user profile N maps to access-control entry N.
Only entries marked enabled=true with required values are configured.
Disabled or omitted entries are left unchanged; the script does not clear entries.
No reboot is performed.
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
LOG_FILE = LOG_DIR / f"configure_snmp_four_profiles_{time.strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("apc-snmp-four-profiles")


def read_json(path):
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("credentials.json must contain a JSON object")
    return data


def read_devices(path):
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    if not rows or "IP" not in rows[0]:
        raise ValueError("device_list.csv must contain an 'IP' header and at least one device")
    return [r["IP"].strip() for r in rows if r.get("IP", "").strip()]


def truthy(value):
    return value is True or str(value).strip().lower() in {"true", "yes", "enabled", "enable", "1"}


def mask_command(command):
    # Mask all values passed to password/community-bearing flags.
    return re.sub(r'(?i)(\s-(?:c|a)\d?\s+)(?:"[^"]*"|\S+)', r'\1<REDACTED>', command)


def build_commands(config):
    commands = []
    snmpv1 = config.get("snmpv1", {})
    for n in range(1, 5):
        item = snmpv1.get(f"profile{n}", {})
        if not isinstance(item, dict) or not truthy(item.get("enabled", False)):
            continue
        ip = str(item.get("nms_ip", "")).strip()
        community = str(item.get("community", "")).strip()
        access = str(item.get("access", "read")).strip().lower()
        if not ip or not community:
            log.warning("SNMPv1 profile %s is enabled but missing nms_ip or community; skipping.", n)
            continue
        if access not in {"read", "write", "writeplus", "disable"}:
            raise ValueError(f"snmpv1.profile{n}.access must be read, write, writeplus, or disable")
        commands.append((
            f"Configure SNMPv1 profile/access entry {n}",
            f'snmp -c{n} "{community}" -a{n} {access} -n{n} {ip}',
            True,
        ))

    snmpv3 = config.get("snmpv3", {})
    if "enabled" in snmpv3:
        commands.append((
            "Set global SNMPv3 state",
            "snmpv3 -S enable" if truthy(snmpv3["enabled"]) else "snmpv3 -S disable",
            False,
        ))

    for n in range(1, 5):
        item = snmpv3.get(f"profile{n}", {})
        if not isinstance(item, dict) or not truthy(item.get("enabled", False)):
            continue
        username = str(item.get("username", "")).strip()
        ip = str(item.get("nms_ip", "")).strip()
        auth = str(item.get("auth_passphrase", "")).strip()
        privacy = str(item.get("privacy_passphrase", "")).strip()
        auth_protocol = str(item.get("auth_protocol", "sha")).strip().lower()
        privacy_protocol = str(item.get("privacy_protocol", "aes")).strip().lower()
        if not all((username, ip, auth, privacy)):
            log.warning("SNMPv3 profile %s is enabled but missing username, nms_ip, auth_passphrase, or privacy_passphrase; skipping.", n)
            continue
        if auth_protocol not in {"sha", "md5", "none"}:
            raise ValueError(f"snmpv3.profile{n}.auth_protocol must be sha, md5, or none")
        if privacy_protocol not in {"aes", "des", "none"}:
            raise ValueError(f"snmpv3.profile{n}.privacy_protocol must be aes, des, or none")
        commands.append((
            f"Configure SNMPv3 user profile {n}",
            f'snmpv3 -u{n} "{username}" -ap{n} {auth_protocol} -pp{n} {privacy_protocol} -a{n} "{auth}" -c{n} "{privacy}"',
            True,
        ))
        commands.append((
            f"Configure SNMPv3 access-control entry {n}",
            f'snmpv3 -ac{n} enable -au{n} "{username}" -n{n} {ip}',
            False,
        ))
    return commands


def connect(host, ssh):
    attempts = [
        (ssh.get("username"), ssh.get("password")),
        (ssh.get("alt_username"), ssh.get("alt_password")),
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


def run_command(shell, command, timeout=15):
    if shell.recv_ready():
        try:
            shell.recv(65535)
        except Exception:
            pass
    shell.send(command + "\r\n")
    output = ""
    deadline = time.time() + timeout
    last_data = None
    while time.time() < deadline:
        if shell.recv_ready():
            output += shell.recv(65535).decode("utf-8", errors="replace")
            last_data = time.time()
            if re.search(r"(?m)apc>\s*$", output):
                break
        elif last_data and time.time() - last_data > 1:
            break
        else:
            time.sleep(0.15)
    return output.strip()


def response_ok(output):
    if re.search(r"\bE000:\s*Success\b", output, re.I):
        return True
    if re.search(r"\bE00[1-9]:", output, re.I):
        return False
    return bool(output.strip()) and not re.search(r"\b(?:invalid command|syntax error|error:)\b", output, re.I)


def redact_output(output, config):
    secrets = []
    for group_name in ("snmpv1", "snmpv3"):
        group = config.get(group_name, {})
        for item in group.values():
            if isinstance(item, dict):
                for key in ("community", "auth_passphrase", "privacy_passphrase"):
                    val = item.get(key)
                    if val:
                        secrets.append(str(val))
    ssh = config.get("ssh", {})
    for key in ("password", "alt_password"):
        if ssh.get(key):
            secrets.append(str(ssh[key]))
    for secret in sorted(set(secrets), key=len, reverse=True):
        output = output.replace(secret, "<REDACTED>")
    return output


def configure_device(host, config, commands):
    client = None
    try:
        client = connect(host, config.get("ssh", {}))
        shell = client.invoke_shell(width=180, height=50)
        time.sleep(0.5)
        if shell.recv_ready():
            shell.recv(65535)
        log.info("[%s] Connected over SSH.", host)
        results = []
        for label, command, contains_secret in commands:
            log.info("[%s] %s: %s", host, label, mask_command(command) if contains_secret else command)
            output = run_command(shell, command)
            ok = response_ok(output)
            log.info("[%s] %s: %s | response=%s", host, "Success" if ok else "Unconfirmed",
                     label, redact_output(output, config).replace("\n", " | ")[:1800])
            results.append(ok)

        for command in ("snmp", "snmpv3"):
            output = run_command(shell, command)
            log.info("[%s] %s readback: %s", host, command, redact_output(output, config).replace("\n", " | ")[:5000])

        if not commands:
            status = "NO CHANGES"
        elif all(results):
            status = "COMMANDS ACCEPTED (review readback)"
        else:
            status = "PARTIAL (inspect log/readback)"
        return host, status
    except Exception as exc:
        log.exception("[%s] Configuration failed: %s", host, exc)
        return host, f"FAILED: {exc}"
    finally:
        if client:
            client.close()


def main():
    try:
        config = read_json(CREDENTIALS_FILE)
        ssh = config.get("ssh", {})
        if not ssh.get("username") or not ssh.get("password"):
            raise ValueError("credentials.json requires ssh.username and ssh.password")
        devices = read_devices(DEVICE_FILE)
        commands = build_commands(config)
    except Exception as exc:
        print(f"Setup error: {exc}")
        raise SystemExit(2)

    if not commands:
        print("No applicable SNMP entries found. Check enabled flags and JSON values.")
        raise SystemExit(2)

    print(f"Devices: {len(devices)} | Commands per device: {len(commands)}")
    print(f"Log: {LOG_FILE}")
    print("Only enabled entries with required fields will be configured; omitted/disabled entries are not cleared.")
    print("No reboot will be performed. Test on one UPS first.")
    for host in devices:
        device, status = configure_device(host, config, commands)
        print(f"[{device}] {status}")


if __name__ == "__main__":
    main()
