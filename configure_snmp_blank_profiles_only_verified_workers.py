#!/usr/bin/env python3
"""
Safely configure only confirmed-blank APC NMC SNMPv1/v3 slots (NMC2/NMC3).

Safety:
- Never modify SNMPv3 user profile 1 or SNMPv3 access-control entry 1.
- Never change global SNMP/SNMPv3 enable state; never reboot.
- Never overwrite configured or ambiguous slots.
- SNMPv3 user-profile indexes and access-control indexes are checked independently.
- If a write response is ambiguous, read back state before deciding; stop further writes.
- Logs redact configured secrets.

Run:
  py .\configure_snmp_blank_profiles_only_verified_workers.py --workers 5 --dry-run
  py .\configure_snmp_blank_profiles_only_verified_workers.py --workers 1 --host 10.0.0.1
  py .\configure_snmp_blank_profiles_only_verified_workers.py --workers 10 --conn-timeout 20 --cmd-timeout 30
"""

import argparse
import csv
import json
import logging
import re
import signal
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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
LOG_FILE = LOG_DIR / f"configure_snmp_blank_profiles_only_{time.strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8")],
)
log = logging.getLogger("apc-snmp-blank-only")
_stop = False


def read_json(path):
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("credentials.json must contain a JSON object")
    return data


def read_devices(path):
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "IP" not in reader.fieldnames:
            raise ValueError("device_list.csv must contain an 'IP' header")
        rows = list(reader)
    devices = [str(r.get("IP", "")).strip() for r in rows if str(r.get("IP", "")).strip()]
    if not devices:
        raise ValueError("device_list.csv contains no device IPs")
    return devices


def truthy(value):
    return value is True or str(value).strip().lower() in {"true", "yes", "enabled", "enable", "1"}


def norm(value):
    return re.sub(r"\s+", " ", str(value or "").strip()).lower()


def redact_text(text, config):
    secrets = []
    for group_name in ("snmpv1", "snmpv3"):
        group = config.get(group_name, {})
        if isinstance(group, dict):
            for item in group.values():
                if isinstance(item, dict):
                    for key in ("community", "auth_passphrase", "privacy_passphrase"):
                        if item.get(key):
                            secrets.append(str(item[key]))
    ssh = config.get("ssh", {})
    if isinstance(ssh, dict):
        for key in ("password", "alt_password"):
            if ssh.get(key):
                secrets.append(str(ssh[key]))
    for secret in sorted(set(secrets), key=len, reverse=True):
        text = text.replace(secret, "<REDACTED>")
    return text


def mask_command(command):
    # Commands are logged only in masked form; redact values after credential-bearing flags.
    command = re.sub(r'(?i)(-c\d?\s+)(?:"[^"]*"|\S+)', r'\1<REDACTED>', command)
    command = re.sub(r'(?i)(-a\d?\s+)(?:"[^"]*"|\S+)', r'\1<REDACTED>', command)
    return command


def connect(host, ssh_cfg, timeout):
    attempts = [
        (ssh_cfg.get("username"), ssh_cfg.get("password")),
        (ssh_cfg.get("alt_username"), ssh_cfg.get("alt_password")),
    ]
    errors = []
    for username, password in attempts:
        if not username or not password:
            continue
        client = paramiko.SSHClient()
        # Keep the host-key behavior explicit and configurable. AutoAddPolicy is retained
        # for compatibility with unmanaged APC fleets; use known_hosts for stricter trust.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host, username=username, password=password,
                timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                look_for_keys=False, allow_agent=False,
            )
            return client
        except Exception as exc:
            errors.append(f"{username}: {type(exc).__name__}: {exc}")
            client.close()
    raise RuntimeError("SSH connection failed: " + "; ".join(errors or ["no SSH credentials configured"]))


ANSI_RE = re.compile(r"\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\))")


def clean_text(text):
    text = ANSI_RE.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    out = []
    for ch in text:
        if ch == "\x08":
            if out:
                out.pop()
        elif ch != "\x00":
            out.append(ch)
    return "".join(out)


def prompt_present(text):
    # Accept the documented APC prompt and common device-name prompts ending in >.
    lines = [line.strip() for line in clean_text(text).splitlines() if line.strip()]
    return bool(lines and re.fullmatch(r"(?:[A-Za-z0-9_.-]+)?\s*>", lines[-1]))


def wait_for_prompt(shell, timeout):
    buf = ""
    deadline = time.monotonic() + timeout
    stable_since = None
    while time.monotonic() < deadline:
        if shell.recv_ready():
            buf += shell.recv(65535).decode("utf-8", errors="replace")
            if prompt_present(buf):
                stable_since = stable_since or time.monotonic()
            else:
                stable_since = None
        else:
            if stable_since is not None and time.monotonic() - stable_since >= 0.3:
                while shell.recv_ready():
                    buf += shell.recv(65535).decode("utf-8", errors="replace")
                if prompt_present(buf):
                    return clean_text(buf)
                stable_since = None
            time.sleep(0.05)
    raise RuntimeError("Timed out waiting for APC CLI prompt before issuing commands. Partial output: " +
                       clean_text(buf)[-1200:].replace("\n", " | "))


def run_command(shell, command, timeout):
    # Do not issue a command if unexpected output is already buffered; command/response
    # alignment would be uncertain and a write could become unsafe.
    if shell.recv_ready():
        stale = clean_text(shell.recv(65535).decode("utf-8", errors="replace"))
        if stale.strip():
            raise RuntimeError("Unexpected buffered SSH output before command; refusing to send. Output: " +
                               stale[-800:].replace("\n", " | "))
    shell.send(command + "\r\n")
    buf = ""
    deadline = time.monotonic() + timeout
    stable_since = None
    while time.monotonic() < deadline:
        if shell.recv_ready():
            buf += shell.recv(65535).decode("utf-8", errors="replace")
            if prompt_present(buf):
                stable_since = stable_since or time.monotonic()
            else:
                stable_since = None
        else:
            if stable_since is not None and time.monotonic() - stable_since >= 0.35:
                while shell.recv_ready():
                    buf += shell.recv(65535).decode("utf-8", errors="replace")
                if prompt_present(buf):
                    lines = clean_text(buf).strip().splitlines()
                    if lines and re.fullmatch(r"(?:[A-Za-z0-9_.-]+)?\s*>", lines[-1].strip()):
                        lines = lines[:-1]
                    return "\n".join(lines).strip(), False
                stable_since = None
            time.sleep(0.05)
    return clean_text(buf).strip(), True


def outcome_class(output, partial=False):
    if re.search(r"\bE000:\s*Success\b", output, re.I):
        return "success"
    if re.search(r"\bE00[1-9]:", output, re.I):
        return "failure"
    # Some firmware returns explicit success text without E000; treat it as ambiguous,
    # never as confirmed success. The caller will perform readback.
    return "ambiguous"


def parse_blocks(text, patterns):
    blocks = {}
    current = None
    for raw_line in clean_text(text).splitlines():
        line = raw_line.strip()
        m = re.search(r"(?:Access\s+Control\s*#|Access\s+Control\s+Entry\s*#?|User\s+Profile\s*#?|Index)\s*:?\s*(\d+)\b", line, re.I)
        if m:
            current = int(m.group(1))
            blocks.setdefault(current, {})
            continue
        # Also accept labels formatted as "Access Control 2" or "User Profile 2".
        m = re.match(r"(?:Access\s+Control(?:\s+Entry)?|User\s+Profile)\s+(\d+)\s*:?\s*$", line, re.I)
        if m:
            current = int(m.group(1))
            blocks.setdefault(current, {})
            continue
        if current is None:
            continue
        for key, pattern in patterns.items():
            match = re.search(pattern, line, re.I)
            if match:
                blocks[current][key] = match.group(1).strip()
    return blocks


def split_v3_sections(text):
    # Require distinct headings to avoid interpreting one table as both users and ACLs.
    user_match = re.search(r"(?:SNMPv3\s+)?User\s+Profiles?\b", text, re.I)
    access_match = re.search(r"(?:SNMPv3\s+)?Access\s+Control(?:\s+Entries)?\b", text, re.I)
    if not user_match or not access_match or access_match.start() <= user_match.start():
        raise RuntimeError("Could not safely identify separate SNMPv3 User Profiles and Access Control sections")
    return text[user_match.end():access_match.start()], text[access_match.end():]


def read_device_state(shell, host, config, phase, timeout):
    out1, partial1 = run_command(shell, "snmp", timeout)
    out3, partial3 = run_command(shell, "snmpv3", timeout)
    if partial1 or partial3 or not out1 or not out3:
        raise RuntimeError(f"{phase}: incomplete/timeout read (snmp partial={partial1}, snmpv3 partial={partial3}); "
                           f"snmp={out1[-500:]!r}; snmpv3={out3[-500:]!r}")
    user_section, access_section = split_v3_sections(out3)

    v1 = parse_blocks(out1, {
        "community": r"Community\s*:\s*(.*?)\s*$",
        "access": r"Access\s*(?:Type)?\s*:\s*(.*?)\s*$",
        "address": r"(?:NMS\s*IP/Host\s*Name|NMS\s*IP|Address)\s*:\s*(.*?)\s*$",
    })
    v3_users = parse_blocks(user_section, {
        "username": r"(?:User\s*Name|Username)\s*:\s*(.*?)\s*$",
        "authentication": r"(?:Authentication\s*(?:Protocol)?|Auth)\s*:\s*(.*?)\s*$",
        "encryption": r"(?:Encryption\s*(?:Protocol)?|Privacy)\s*:\s*(.*?)\s*$",
    })
    v3_access = parse_blocks(access_section, {
        "username": r"(?:User\s*Name|Username|Access\s*User\s*Profile\s*Name)\s*:\s*(.*?)\s*$",
        "access": r"(?:Access|Status)\s*:\s*(.*?)\s*$",
        "address": r"(?:NMS\s*IP/Host\s*Name|NMS\s*IP|Address)\s*:\s*(.*?)\s*$",
    })

    for n in range(1, 5):
        if n not in v1 or not all(k in v1[n] for k in ("community", "access", "address")):
            raise RuntimeError(f"{phase}: SNMPv1 entry {n} readback incomplete; refusing writes")
        if n not in v3_users or not all(k in v3_users[n] for k in ("username", "authentication", "encryption")):
            raise RuntimeError(f"{phase}: SNMPv3 user profile {n} readback incomplete; refusing writes")
        if n not in v3_access or not all(k in v3_access[n] for k in ("username", "access", "address")):
            raise RuntimeError(f"{phase}: SNMPv3 access entry {n} readback incomplete; refusing writes")

    log.info("[%s] %s SNMPv1 readback: %s", host, phase,
             redact_text(out1, config).replace("\n", " | ")[:5000])
    log.info("[%s] %s SNMPv3 readback: %s", host, phase,
             redact_text(out3, config).replace("\n", " | ")[:7000])
    return v1, v3_users, v3_access


def slot_is_blank_v1(entry):
    return (norm(entry.get("community")) == "public"
            and norm(entry.get("access")) in {"disabled", "disable"}
            and norm(entry.get("address")) == "0.0.0.0")


def slot_is_blank_v3_user(user, index):
    placeholder = f"apc snmp profile{index}"
    return (norm(user.get("username")) == placeholder
            and norm(user.get("authentication")) == "none"
            and norm(user.get("encryption")) == "none")


def slot_is_blank_v3_access(entry, index):
    placeholder = f"apc snmp profile{index}"
    return (norm(entry.get("username")) == placeholder
            and norm(entry.get("access")) in {"disabled", "disable"}
            and norm(entry.get("address")) == "0.0.0.0")


def build_blank_slot_commands(config, state, host, dry_run=False):
    v1_state, v3_users, v3_access = state
    commands = []

    for index in range(1, 5):
        item = config.get("snmpv1", {}).get(f"profile{index}", {})
        if not isinstance(item, dict) or not truthy(item.get("enabled", False)):
            continue
        existing = v1_state.get(index)
        if not existing or not slot_is_blank_v1(existing):
            log.info("[%s] SNMPv1 entry %s is configured/ambiguous; leaving unchanged.", host, index)
            continue
        ip = str(item.get("nms_ip", "")).strip()
        community = str(item.get("community", "")).strip()
        access = str(item.get("access", "read")).strip().lower()
        if not ip or not community:
            log.warning("[%s] SNMPv1 profile %s missing nms_ip/community; skipping.", host, index)
            continue
        if access not in {"read", "write", "writeplus", "disable"}:
            raise ValueError(f"snmpv1.profile{index}.access must be read, write, writeplus, or disable")
        commands.append((f"Configure blank SNMPv1 entry {index}",
                         f'snmp -c{index} "{community}" -a{index} {access} -n{index} {ip}',
                         True, ("v1", index)))

    for index in range(2, 5):  # Deliberately never touch SNMPv3 profile/access entry 1.
        item = config.get("snmpv3", {}).get(f"profile{index}", {})
        if not isinstance(item, dict) or not truthy(item.get("enabled", False)):
            continue
        user = v3_users.get(index)
        access_entry = v3_access.get(index)
        if not user or not access_entry:
            log.warning("[%s] SNMPv3 index %s state missing; skipping.", host, index)
            continue
        username = str(item.get("username", "")).strip()
        ip = str(item.get("nms_ip", "")).strip()
        auth = str(item.get("auth_passphrase", "")).strip()
        privacy = str(item.get("privacy_passphrase", "")).strip()
        auth_protocol = str(item.get("auth_protocol", "sha")).strip().lower()
        privacy_protocol = str(item.get("privacy_protocol", "aes")).strip().lower()
        if not all((username, ip, auth, privacy)):
            log.warning("[%s] SNMPv3 profile %s missing required fields; skipping.", host, index)
            continue
        if auth_protocol not in {"sha", "md5", "none"}:
            raise ValueError(f"snmpv3.profile{index}.auth_protocol must be sha, md5, or none")
        if privacy_protocol not in {"aes", "des", "none"}:
            raise ValueError(f"snmpv3.profile{index}.privacy_protocol must be aes, des, or none")

        if slot_is_blank_v3_user(user, index):
            commands.append((f"Configure blank SNMPv3 user profile {index}",
                             f'snmpv3 -u{index} "{username}" -ap{index} {auth_protocol} '
                             f'-pp{index} {privacy_protocol} -a{index} "{auth}" -c{index} "{privacy}"',
                             True, ("v3_user", index)))
        else:
            log.info("[%s] SNMPv3 user profile %s is configured/ambiguous; leaving unchanged.", host, index)

        if slot_is_blank_v3_access(access_entry, index):
            commands.append((f"Configure blank SNMPv3 access-control entry {index}",
                             f'snmpv3 -ac{index} enable -au{index} "{username}" -n{index} {ip}',
                             False, ("v3_access", index)))
        else:
            log.info("[%s] SNMPv3 access entry %s is configured/ambiguous; leaving unchanged.", host, index)

    return commands


def verify_changed(state, config, touched):
    v1_state, v3_users, v3_access = state
    failures = []
    for kind, index in sorted(touched):
        if kind == "v1":
            item = config.get("snmpv1", {}).get(f"profile{index}", {})
            actual = v1_state[index]
            expected_access = str(item.get("access", "read")).strip().lower().replace("writeplus", "write +")
            if norm(actual.get("community")) != norm(item.get("community")):
                failures.append(f"SNMPv1 entry {index} community mismatch")
            if norm(actual.get("access")) != norm(expected_access):
                failures.append(f"SNMPv1 entry {index} access mismatch")
            if norm(actual.get("address")) != norm(item.get("nms_ip")):
                failures.append(f"SNMPv1 entry {index} NMS IP mismatch")
        elif kind == "v3_user":
            item = config.get("snmpv3", {}).get(f"profile{index}", {})
            actual = v3_users[index]
            if norm(actual.get("username")) != norm(item.get("username")):
                failures.append(f"SNMPv3 user profile {index} username mismatch")
            if norm(actual.get("authentication")) != norm(item.get("auth_protocol", "sha")):
                failures.append(f"SNMPv3 user profile {index} authentication mismatch")
            if norm(actual.get("encryption")) != norm(item.get("privacy_protocol", "aes")):
                failures.append(f"SNMPv3 user profile {index} encryption mismatch")
        elif kind == "v3_access":
            item = config.get("snmpv3", {}).get(f"profile{index}", {})
            actual = v3_access[index]
            if norm(actual.get("username")) != norm(item.get("username")):
                failures.append(f"SNMPv3 access entry {index} username mismatch")
            if norm(actual.get("access")) not in {"enabled", "enable"}:
                failures.append(f"SNMPv3 access entry {index} is not enabled")
            if norm(actual.get("address")) != norm(item.get("nms_ip")):
                failures.append(f"SNMPv3 access entry {index} NMS IP mismatch")
    return failures


def configure_device(host, config, conn_timeout, cmd_timeout, dry_run=False):
    client = None
    try:
        client = connect(host, config.get("ssh", {}), conn_timeout)
        shell = client.invoke_shell(width=180, height=50)
        banner = wait_for_prompt(shell, cmd_timeout)
        log.info("[%s] SSH connected; APC CLI prompt ready.", host)
        log.debug("[%s] Initial shell text: %s", host, redact_text(banner, config)[-1500:].replace("\n", " | "))

        preflight = read_device_state(shell, host, config, "Preflight", cmd_timeout)
        commands = build_blank_slot_commands(config, preflight, host)
        if not commands:
            return host, "NO CHANGES (no confirmed blank slots matched enabled JSON profiles)"

        if dry_run:
            for label, command, secret, tag in commands:
                log.info("[%s] DRY RUN %s: %s", host, label, mask_command(command) if secret else command)
            return host, f"DRY RUN ({len(commands)} candidate command(s); no writes sent)"

        touched = set()
        for label, command, contains_secret, tag in commands:
            if _stop:
                return host, "STOPPED (interrupt requested; no more writes)"
            log.info("[%s] %s command: %s", host, label,
                     mask_command(command) if contains_secret else command)
            output, partial = run_command(shell, command, cmd_timeout)
            outcome = outcome_class(output, partial)
            log.info("[%s] %s outcome=%s partial=%s output=%s", host, label, outcome, partial,
                     redact_text(output, config).replace("\n", " | ")[:1800])

            if outcome == "failure":
                raise RuntimeError(f"{label} returned explicit APC error; stopping this device")
            if outcome == "success" and not partial:
                touched.add(tag)
                continue

            # Ambiguous or incomplete response: read back only; do not resend the write.
            log.warning("[%s] %s outcome ambiguous; verifying by readback and stopping further writes.", host, label)
            state = read_device_state(shell, host, config, "Ambiguous-readback", cmd_timeout)
            failures = verify_changed(state, config, {tag})
            if failures:
                raise RuntimeError(f"{label} ambiguous and readback did not confirm it: {failures[0]}")
            touched.add(tag)
            break

        final_state = read_device_state(shell, host, config, "Final", cmd_timeout)
        failures = verify_changed(final_state, config, touched)
        if failures:
            for failure in failures:
                log.error("[%s] Verification failed: %s", host, failure)
            return host, "VERIFICATION FAILED (" + "; ".join(failures) + ")"
        return host, f"VERIFIED ({len(touched)} changed slot component(s))"
    except Exception as exc:
        safe_message = redact_text(str(exc), config)
        log.error("[%s] SAFETY STOP: %s", host, safe_message)
        return host, f"FAILED/SAFETY STOP: {safe_message}"
    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass


def handle_sigint(signum, frame):
    global _stop
    _stop = True
    print("\nCtrl+C received: stopping submission of new devices; active device tasks will finish/timeout.", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Configure only confirmed-blank APC NMC SNMP slots.")
    parser.add_argument("--workers", type=int, default=5, help="Maximum concurrent devices (1-25; default 5)")
    parser.add_argument("--conn-timeout", type=int, default=20, help="SSH connect/auth/banner timeout seconds")
    parser.add_argument("--cmd-timeout", type=int, default=30, help="Per-command timeout seconds")
    parser.add_argument("--host", help="Process only this exact host/IP from device_list.csv")
    parser.add_argument("--dry-run", action="store_true", help="Read and plan changes but send no configuration commands")
    args = parser.parse_args()
    if not 1 <= args.workers <= 25:
        parser.error("--workers must be between 1 and 25")
    if args.conn_timeout < 1 or args.cmd_timeout < 1:
        parser.error("timeouts must be positive")
    signal.signal(signal.SIGINT, handle_sigint)

    try:
        config = read_json(CREDENTIALS_FILE)
        ssh_cfg = config.get("ssh", {})
        if not ssh_cfg.get("username") or not ssh_cfg.get("password"):
            raise ValueError("credentials.json requires ssh.username and ssh.password")
        raw_devices = read_devices(DEVICE_FILE)
        devices = list(dict.fromkeys(raw_devices))
        duplicates = len(raw_devices) - len(devices)
        if args.host:
            if args.host not in devices:
                raise ValueError("--host must exactly match an IP in device_list.csv")
            devices = [args.host]
    except Exception as exc:
        print(f"Setup error: {exc}")
        raise SystemExit(2)

    print(f"Processing {len(devices)} unique device(s); workers={args.workers}; dry_run={args.dry_run}")
    print(f"Log: {LOG_FILE}")
    if duplicates:
        print(f"Removed {duplicates} duplicate device-list row(s).")

    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="apc-nmc") as pool:
        futures = {}
        next_index = 0
        # Keep at most --workers tasks submitted at once so Ctrl+C prevents queueing
        # the remainder of the fleet.
        while next_index < len(devices) or futures:
            while not _stop and next_index < len(devices) and len(futures) < args.workers:
                host = devices[next_index]
                next_index += 1
                futures[pool.submit(configure_device, host, config, args.conn_timeout,
                                    args.cmd_timeout, args.dry_run)] = host
            if not futures:
                break
            done = next((f for f in futures if f.done()), None)
            if done is None:
                time.sleep(0.1)
                continue
            host = futures.pop(done)
            try:
                device, status = done.result()
            except Exception as exc:
                log.exception("[%s] Worker exception", host)
                device, status = host, f"FAILED/SAFETY STOP: {exc}"
            print(f"{device}: {status}", flush=True)
            completed += 1
    print(f"Finished: {completed}/{len(devices)} device task(s) completed. Log: {LOG_FILE}")


if __name__ == "__main__":
    main()
