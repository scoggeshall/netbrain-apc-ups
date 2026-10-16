"""
APC NMC2 SNMP configuration over SSH.

Required files in the same folder:
    configure_snmp.py
    credentials.json
    device_list.csv

Run:
    py configure_snmp.py

Fixed workflow:
    - SSH only
    - 10 workers
    - Configure SNMPv1 and SNMPv3
    - Verify
    - Reboot
    - Wait for SSH
    - Verify again
    - Exit
"""

from __future__ import annotations

import csv
import json
import re
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("ERROR: Paramiko is required. Install it with: pip install paramiko")
    sys.exit(1)


BASE_DIR = Path(__file__).resolve().parent
DEVICE_CSV = BASE_DIR / "device_list.csv"
CREDENTIALS_JSON = BASE_DIR / "credentials.json"
LOG_DIR = BASE_DIR / "Log"

MAX_WORKERS = 10
SSH_PORT = 22
SSH_CONNECT_TIMEOUT = 15
SSH_BANNER_TIMEOUT = 30
SSH_AUTH_TIMEOUT = 20
COMMAND_TIMEOUT = 12
COMMAND_DELAY = 0.35
REBOOT_DOWN_TIMEOUT = 60
REBOOT_UP_TIMEOUT = 180
POLL_INTERVAL = 2

PROMPT_PATTERN = re.compile(rb"(?:^|[\r\n])apc>\s*$")
SUCCESS_CODES = ("E000:", "E002:")
PRINT_LOCK = threading.Lock()


def safe_print(message: str) -> None:
    with PRINT_LOCK:
        print(message, flush=True)


def mask_secrets(text: str, credentials: dict) -> str:
    masked = text
    for key in (
        "ssh_password",
        "alt_password",
        "snmpv3_auth_passphrase",
        "snmpv3_privacy_passphrase",
        "snmpv1_community_1",
        "snmpv1_community_2",
        "snmpv1_community_3",
    ):
        value = credentials.get(key)
        if value:
            masked = masked.replace(str(value), "********")
    return masked


def write_log(
    ip: str,
    summary: list[str],
    session_log: list[str],
    credentials: dict,
) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    path = LOG_DIR / f"{ip}_snmp.log"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    with path.open("a", encoding="utf-8", errors="replace") as handle:
        handle.write("\n" + "=" * 68 + "\n")
        handle.write(f"[{timestamp}] SNMP Configuration\n")
        handle.write("=" * 68 + "\n\n")

        handle.write("Summary\n")
        handle.write("-" * 68 + "\n")
        for line in summary:
            handle.write(mask_secrets(line, credentials) + "\n")

        handle.write("\nSession Log\n")
        handle.write("-" * 68 + "\n")
        for line in session_log:
            handle.write(mask_secrets(line, credentials) + "\n")


def is_ssh_open(ip: str, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, SSH_PORT), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_reboot(ip: str) -> bool:
    safe_print(f"  [{ip}] Waiting for SSH to go offline...")

    deadline = time.time() + REBOOT_DOWN_TIMEOUT
    while time.time() < deadline:
        if not is_ssh_open(ip):
            safe_print(f"  [{ip}] SSH is offline")
            break
        time.sleep(POLL_INTERVAL)

    safe_print(f"  [{ip}] Waiting for SSH to return...")
    deadline = time.time() + REBOOT_UP_TIMEOUT

    while time.time() < deadline:
        if is_ssh_open(ip):
            safe_print(f"  [{ip}] SSH is back online")
            return True
        time.sleep(POLL_INTERVAL)

    safe_print(f"  [{ip}] SSH did not return before timeout")
    return False


class APCSSH:
    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.client: paramiko.SSHClient | None = None
        self.channel = None
        self.username = ""
        self.session_log: list[str] = []

    def connect(self, username: str, password: str) -> bool:
        self.close()

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=self.ip,
                port=SSH_PORT,
                username=username,
                password=password,
                timeout=SSH_CONNECT_TIMEOUT,
                banner_timeout=SSH_BANNER_TIMEOUT,
                auth_timeout=SSH_AUTH_TIMEOUT,
                allow_agent=False,
                look_for_keys=False,
            )

            channel = client.invoke_shell(width=160, height=40)
            channel.settimeout(1.0)

            banner = self._read_until_prompt(channel, COMMAND_TIMEOUT)
            if not PROMPT_PATTERN.search(banner):
                client.close()
                self.session_log.append(
                    f"LOGIN FAILED [{username}] - APC prompt not received"
                )
                return False

            self.client = client
            self.channel = channel
            self.username = username
            self.session_log.append(f"LOGIN SUCCESS [{username}] via SSH")
            return True

        except paramiko.AuthenticationException as exc:
            self.session_log.append(f"SSH AUTH FAILED [{username}]: {exc}")
        except paramiko.SSHException as exc:
            self.session_log.append(f"SSH PROTOCOL ERROR [{username}]: {exc}")
        except OSError as exc:
            self.session_log.append(f"SSH CONNECTION FAILED [{username}]: {exc}")
        except Exception as exc:
            self.session_log.append(f"SSH FAILED [{username}]: {exc}")

        return False

    def _read_until_prompt(self, channel, timeout: float) -> bytes:
        data = b""
        deadline = time.time() + timeout

        while time.time() < deadline:
            if channel.recv_ready():
                chunk = channel.recv(4096)
                if not chunk:
                    break
                data += chunk

                if PROMPT_PATTERN.search(data):
                    break
            else:
                time.sleep(0.05)

        return data

    def _drain(self) -> None:
        if not self.channel:
            return

        quiet_deadline = time.time() + 0.25

        while time.time() < quiet_deadline:
            if self.channel.recv_ready():
                self.channel.recv(4096)
                quiet_deadline = time.time() + 0.15
            else:
                time.sleep(0.03)

    def command(self, command: str) -> str:
        if not self.channel:
            return "ERROR: SSH session is not connected"

        self._drain()
        self.channel.sendall(command + "\r\n")
        time.sleep(COMMAND_DELAY)

        response = self._read_until_prompt(self.channel, COMMAND_TIMEOUT)
        decoded = response.decode("utf-8", errors="replace")

        self.session_log.append(f"CMD: {command}")
        self.session_log.append(f"RSP: {decoded.strip()}")
        return decoded

    def reboot(self) -> str:
        if not self.channel:
            return "ERROR: SSH session is not connected"

        self._drain()
        self.channel.sendall("reboot -Y\r\n")
        time.sleep(1)

        response = b""
        deadline = time.time() + 5

        while time.time() < deadline:
            if self.channel.recv_ready():
                chunk = self.channel.recv(4096)
                if not chunk:
                    break
                response += chunk
            else:
                time.sleep(0.05)

        decoded = response.decode("utf-8", errors="replace")
        self.session_log.append("CMD: reboot -Y")
        self.session_log.append(f"RSP: {decoded.strip()}")
        return decoded

    def close(self) -> None:
        if self.channel:
            try:
                self.channel.sendall("exit\r\n")
                time.sleep(0.2)
            except Exception:
                pass

        if self.client:
            try:
                self.client.close()
            except Exception:
                pass

        self.channel = None
        self.client = None


def check_success(response: str) -> bool:
    return any(code in response for code in SUCCESS_CODES)


def build_commands(credentials: dict) -> list[tuple[str, str]]:
    v1_ip = credentials["snmpv1_nms_ip"]
    community_1 = credentials["snmpv1_community_1"]
    community_2 = credentials["snmpv1_community_2"]
    community_3 = credentials["snmpv1_community_3"]

    username = credentials["snmpv3_username"]
    v3_ip_1 = credentials["snmpv3_nms_ip_1"]
    v3_ip_2 = credentials["snmpv3_nms_ip_2"]
    auth_phrase = credentials["snmpv3_auth_passphrase"]
    privacy_phrase = credentials["snmpv3_privacy_passphrase"]

    return [
        ("Enable SNMPv1", "snmp -S enable"),
        (
            "SNMPv1 access 1",
            f"snmp -c1 {community_1} -a1 read -n1 {v1_ip}",
        ),
        (
            "SNMPv1 access 2",
            f"snmp -c2 {community_2} -a2 read -n2 {v1_ip}",
        ),
        (
            "SNMPv1 access 3",
            f"snmp -c3 {community_3} -a3 read -n3 {v1_ip}",
        ),
        (
            "Disable SNMPv1 access 4",
            "snmp -c4 public -a4 disable -n4 0.0.0.0",
        ),
        ("Enable SNMPv3", "snmpv3 -S enable"),
        (
            "Configure SNMPv3 user profile 1",
            f"snmpv3 -u1 {username} -ap1 sha -pp1 aes "
            f"-a1 {auth_phrase} -c1 {privacy_phrase}",
        ),
        (
            "Enable SNMPv3 access 1",
            f"snmpv3 -ac1 enable -au1 {username} -n1 {v3_ip_1}",
        ),
        (
            "Enable SNMPv3 access 2",
            f"snmpv3 -ac2 enable -au2 {username} -n2 {v3_ip_2}",
        ),
        (
            "Disable SNMPv3 access 3",
            "snmpv3 -ac3 disable -n3 0.0.0.0",
        ),
        (
            "Disable SNMPv3 access 4",
            "snmpv3 -ac4 disable -n4 0.0.0.0",
        ),
        (
            "Reset SNMPv3 user profile 2",
            'snmpv3 -u2 "apc snmp profile2" -ap2 none -pp2 none',
        ),
        (
            "Reset SNMPv3 user profile 3",
            'snmpv3 -u3 "apc snmp profile3" -ap3 none -pp3 none',
        ),
        (
            "Reset SNMPv3 user profile 4",
            'snmpv3 -u4 "apc snmp profile4" -ap4 none -pp4 none',
        ),
    ]


def verify(session: APCSSH) -> tuple[bool, list[str]]:
    summary: list[str] = []
    passed = True

    for name, command in (("SNMPv1", "snmp"), ("SNMPv3", "snmpv3")):
        response = session.command(command)
        command_passed = check_success(response)
        passed = passed and command_passed

        summary.append(
            f"{name} verification: {'PASS' if command_passed else 'FAIL'}"
        )
        summary.append(response.strip())

    return passed, summary


def connect_device(ip: str, credentials: dict) -> APCSSH | None:
    candidates = [
        (credentials["ssh_username"], credentials["ssh_password"])
    ]

    if credentials.get("alt_username") and credentials.get("alt_password"):
        candidates.append(
            (credentials["alt_username"], credentials["alt_password"])
        )

    session = APCSSH(ip)

    for username, password in candidates:
        safe_print(f"  [{ip}] Trying SSH as '{username}'...")

        if session.connect(username, password):
            safe_print(f"  [{ip}] Connected via SSH")
            return session

    return None


def configure_device(ip: str, credentials: dict) -> str:
    safe_print("")
    safe_print("=" * 68)
    safe_print(f"  [{ip}] Starting SNMP configuration")
    safe_print("=" * 68)

    summary: list[str] = []
    full_session_log: list[str] = []

    if not is_ssh_open(ip):
        safe_print(f"  [{ip}] SSH port 22 is not reachable")
        summary.append("FAILED: SSH port 22 is not reachable")
        write_log(ip, summary, full_session_log, credentials)
        return f"{ip}:FAILED"

    session = connect_device(ip, credentials)

    if not session:
        safe_print(f"  [{ip}] SSH authentication failed")
        summary.append("FAILED: SSH authentication failed")
        write_log(ip, summary, full_session_log, credentials)
        return f"{ip}:FAILED"

    summary.append(f"Connected via SSH as '{session.username}'")
    command_failed = False

    try:
        for description, command in build_commands(credentials):
            safe_print(f"  [{ip}] {description}")
            response = session.command(command)

            if check_success(response):
                safe_print(f"  [{ip}]   Success")
                summary.append(f"OK: {description}")
            else:
                safe_print(f"  [{ip}]   Failed")
                summary.append(f"FAIL: {description}")
                command_failed = True

        safe_print(f"  [{ip}] Verifying before reboot...")
        verified, verification_summary = verify(session)
        summary.extend(verification_summary)
        full_session_log.extend(session.session_log)

        if command_failed or not verified:
            safe_print(f"  [{ip}] Configuration incomplete; reboot skipped")
            summary.append(
                "FAILED: Reboot skipped because configuration did not verify"
            )
            write_log(ip, summary, full_session_log, credentials)
            return f"{ip}:PARTIAL"

        safe_print(f"  [{ip}] Rebooting...")
        session.reboot()
        summary.append("Reboot command sent")
        full_session_log = list(session.session_log)
        session.close()

        if not wait_for_reboot(ip):
            summary.append("FAILED: SSH did not return after reboot")
            write_log(ip, summary, full_session_log, credentials)
            return f"{ip}:FAILED"

        safe_print(f"  [{ip}] Reconnecting after reboot...")
        post_session = connect_device(ip, credentials)

        if not post_session:
            summary.append("FAILED: Could not reconnect after reboot")
            write_log(ip, summary, full_session_log, credentials)
            return f"{ip}:FAILED"

        post_verified, post_summary = verify(post_session)
        summary.extend(post_summary)
        full_session_log.extend(post_session.session_log)
        post_session.close()

        if not post_verified:
            safe_print(f"  [{ip}] Post-reboot verification failed")
            summary.append("FAILED: Post-reboot verification failed")
            write_log(ip, summary, full_session_log, credentials)
            return f"{ip}:FAILED"

        safe_print(f"  [{ip}] Completed successfully")
        summary.append("SUCCESS")
        write_log(ip, summary, full_session_log, credentials)
        return f"{ip}:SUCCESS"

    finally:
        session.close()


def load_credentials() -> dict:
    if not CREDENTIALS_JSON.exists():
        raise FileNotFoundError(f"Missing file: {CREDENTIALS_JSON}")

    with CREDENTIALS_JSON.open("r", encoding="utf-8") as handle:
        credentials = json.load(handle)

    required = (
        "ssh_username",
        "ssh_password",
        "snmpv1_nms_ip",
        "snmpv1_community_1",
        "snmpv1_community_2",
        "snmpv1_community_3",
        "snmpv3_username",
        "snmpv3_nms_ip_1",
        "snmpv3_nms_ip_2",
        "snmpv3_auth_passphrase",
        "snmpv3_privacy_passphrase",
    )

    missing = [
        key for key in required
        if not str(credentials.get(key, "")).strip()
    ]

    if missing:
        raise ValueError(
            "Missing or blank credentials.json values: "
            + ", ".join(missing)
        )

    communities = {
        credentials["snmpv1_community_1"],
        credentials["snmpv1_community_2"],
        credentials["snmpv1_community_3"],
    }

    if len(communities) != 3:
        raise ValueError("The three SNMPv1 community names must be unique")

    if credentials["snmpv3_nms_ip_1"] == credentials["snmpv3_nms_ip_2"]:
        raise ValueError("The two SNMPv3 NMS IP addresses must be different")

    return credentials


def load_devices() -> list[str]:
    if not DEVICE_CSV.exists():
        raise FileNotFoundError(f"Missing file: {DEVICE_CSV}")

    devices: list[str] = []

    with DEVICE_CSV.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)

        if not reader.fieldnames or "IP" not in reader.fieldnames:
            raise ValueError("device_list.csv must contain an IP header")

        for row in reader:
            ip = str(row.get("IP", "")).strip()

            if ip:
                devices.append(ip)

    if not devices:
        raise ValueError("device_list.csv contains no device IP addresses")

    return devices


def print_summary(results: list[str], elapsed: float) -> None:
    successful = [item for item in results if item.endswith(":SUCCESS")]
    partial = [item for item in results if item.endswith(":PARTIAL")]
    failed = [item for item in results if item.endswith(":FAILED")]

    print("")
    print("=" * 68)
    print("SNMP CONFIGURATION SUMMARY")
    print("=" * 68)
    print(f"Total devices: {len(results)}")
    print(f"Successful:    {len(successful)}")
    print(f"Partial:       {len(partial)}")
    print(f"Failed:        {len(failed)}")
    print(f"Total time:    {elapsed / 60:.1f} minutes")
    print(f"Logs:          {LOG_DIR}")

    if partial:
        print("")
        print("Partial:")
        for item in partial:
            print(f"  {item.split(':', 1)[0]}")

    if failed:
        print("")
        print("Failed:")
        for item in failed:
            print(f"  {item.split(':', 1)[0]}")


def main() -> None:
    try:
        credentials = load_credentials()
        devices = load_devices()
    except (
        FileNotFoundError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

    start = time.time()

    print("APC NMC2 SNMP Configuration")
    print(f"Devices: {len(devices)} | Workers: {MAX_WORKERS}")
    print("=" * 68)

    results: list[str] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(configure_device, ip, credentials): ip
            for ip in devices
        }

        for future in as_completed(futures):
            ip = futures[future]

            try:
                results.append(future.result())
            except Exception as exc:
                safe_print(f"  [{ip}] Unhandled error: {exc}")
                results.append(f"{ip}:FAILED")

    print_summary(results, time.time() - start)


if __name__ == "__main__":
    main()