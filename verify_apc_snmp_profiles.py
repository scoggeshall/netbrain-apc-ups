"""Read-only APC NMC SNMP profile verification; sends only `snmp` and `snmpv3`."""

from __future__ import annotations

import argparse
import csv
import logging
import signal
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

from apc_snmp_profiles import (
    PROMPT_RE,
    clean_cli_text,
    verification_row,
    write_verification_csv,
)

BASE = Path(__file__).resolve().parent
_stop = False
log = logging.getLogger("apc-snmp-readonly-verifier")


def read_credentials(path: Path) -> dict:
    import json

    with path.open("r", encoding="utf-8-sig") as stream:
        config = json.load(stream)
    if not isinstance(config, dict) or not isinstance(config.get("ssh"), dict):
        raise TypeError("credentials file must contain an ssh object")
    if not config["ssh"].get("username") or not config["ssh"].get("password"):
        raise ValueError("credentials file requires ssh.username and ssh.password")
    return config


def read_devices(path: Path) -> list[str]:
    with path.open("r", newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or "IP" not in reader.fieldnames:
            raise ValueError("device list must contain an 'IP' header")
        devices = [str(row.get("IP", "")).strip() for row in reader]
    devices = list(dict.fromkeys(device for device in devices if device))
    if not devices:
        raise ValueError("device list contains no device IPs")
    return devices


def connect(host: str, ssh_cfg: dict, timeout: int):
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError(
            "paramiko is required; install it with `python -m pip install paramiko`"
        ) from exc

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    known_hosts = ssh_cfg.get("known_hosts")
    if known_hosts:
        client.load_host_keys(str(Path(known_hosts).expanduser()))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    attempts = (
        (ssh_cfg.get("username"), ssh_cfg.get("password")),
        (ssh_cfg.get("alt_username"), ssh_cfg.get("alt_password")),
    )
    errors = []
    for username, password in attempts:
        if not username or not password:
            continue
        try:
            client.connect(
                hostname=host,
                username=username,
                password=password,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            return client
        except (paramiko.SSHException, OSError, TimeoutError) as exc:
            errors.append(type(exc).__name__)
    client.close()
    raise RuntimeError("SSH connection failed (" + ", ".join(errors or ["no credentials"]) + ")")


def _prompt_present(output: str) -> bool:
    lines = [line.strip() for line in clean_cli_text(output).splitlines() if line.strip()]
    return bool(lines and PROMPT_RE.fullmatch(lines[-1]))


def _receive_until_prompt(shell, timeout: int) -> tuple[str, bool]:
    output = ""
    deadline = time.monotonic() + timeout
    prompt_seen_at = None
    while time.monotonic() < deadline:
        if shell.recv_ready():
            output += shell.recv(65535).decode("utf-8", errors="replace")
            prompt_seen_at = time.monotonic() if _prompt_present(output) else None
        elif prompt_seen_at is not None:
            if time.monotonic() - prompt_seen_at >= 0.3:
                while shell.recv_ready():
                    output += shell.recv(65535).decode("utf-8", errors="replace")
                if _prompt_present(output):
                    cleaned = clean_cli_text(output)
                    lines = cleaned.splitlines()
                    if lines and PROMPT_RE.fullmatch(lines[-1].strip()):
                        lines.pop()
                    return "\n".join(lines).strip(), False
                prompt_seen_at = None
        else:
            time.sleep(0.05)
    return clean_cli_text(output).strip(), True


def run_read_only_command(shell, command: str, timeout: int) -> tuple[str, bool]:
    if command not in {"snmp", "snmpv3"}:
        raise ValueError("command is not in the read-only verifier allowlist")
    if shell.recv_ready():
        stale = clean_cli_text(shell.recv(65535).decode("utf-8", errors="replace"))
        if stale.strip():
            raise RuntimeError("unexpected buffered CLI output; stopping without another command")
    shell.sendall((command + "\r\n").encode("utf-8"))
    return _receive_until_prompt(shell, timeout)


def verify_device(host: str, config: dict, conn_timeout: int, cmd_timeout: int) -> dict[str, str]:
    client = None
    v1_output = ""
    v3_output = ""
    v1_partial = True
    v3_partial = True
    try:
        client = connect(host, config["ssh"], conn_timeout)
        shell = client.invoke_shell(width=240, height=60)
        _, prompt_partial = _receive_until_prompt(shell, cmd_timeout)
        if prompt_partial:
            return verification_row(
                host,
                "",
                "",
                connection_status="CONNECTED",
                v1_partial=True,
                v3_partial=True,
                error="Timed out waiting for APC CLI prompt",
            )
        if _stop:
            return verification_row(
                host,
                "",
                "",
                connection_status="CONNECTED",
                v1_partial=True,
                v3_partial=True,
                error="Interrupted before readback",
            )
        v1_output, v1_partial = run_read_only_command(shell, "snmp", cmd_timeout)
        if not v1_partial and not _stop:
            v3_output, v3_partial = run_read_only_command(shell, "snmpv3", cmd_timeout)
        else:
            v3_partial = True
        return verification_row(
            host,
            v1_output,
            v3_output,
            v1_partial=v1_partial,
            v3_partial=v3_partial,
        )
    except (OSError, TimeoutError, RuntimeError) as exc:
        is_connected = client is not None
        return verification_row(
            host,
            v1_output,
            v3_output,
            connection_status="CONNECTED" if is_connected else "UNREACHABLE",
            v1_partial=True,
            v3_partial=True,
            error=f"{type(exc).__name__}: {'CLI read failed' if is_connected else 'SSH connection failed'}",
        )
    finally:
        if client is not None:
            client.close()


def handle_sigint(signum, frame) -> None:
    global _stop
    _stop = True
    print("\nInterrupt received; no new devices will be submitted.", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", type=Path, default=BASE / "credentials.json")
    parser.add_argument("--devices", type=Path, default=BASE / "device_list.csv")
    parser.add_argument("--host", help="Verify only this exact IP from the device list")
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--conn-timeout", type=int, default=20)
    parser.add_argument("--cmd-timeout", type=int, default=30)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.workers <= 25:
        parser.error("--workers must be between 1 and 25")
    if args.conn_timeout < 1 or args.cmd_timeout < 1:
        parser.error("timeouts must be positive")
    try:
        config = read_credentials(args.credentials)
        devices = read_devices(args.devices)
        if args.host:
            if args.host not in devices:
                raise ValueError("--host must exactly match an IP in the device list")
            devices = [args.host]
    except (OSError, ValueError, csv.Error) as exc:
        parser.error(str(exc))
    output_path = args.output or (
        BASE / "Log" / f"snmp_profile_verification_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    )
    output_path = output_path if output_path.is_absolute() else BASE / output_path
    log_path = output_path.with_suffix(".log")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    signal.signal(signal.SIGINT, handle_sigint)
    print(f"Read-only verification: {len(devices)} device(s), workers={args.workers}")
    print(f"CSV: {output_path}")

    rows: list[dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="apc-verify") as pool:
        futures: dict[Future, str] = {}
        next_index = 0
        while next_index < len(devices) or futures:
            while not _stop and next_index < len(devices) and len(futures) < args.workers:
                host = devices[next_index]
                next_index += 1
                futures[
                    pool.submit(verify_device, host, config, args.conn_timeout, args.cmd_timeout)
                ] = host
            if not futures:
                break
            done = next((future for future in futures if future.done()), None)
            if done is None:
                time.sleep(0.1)
                continue
            host = futures.pop(done)
            try:
                row = done.result()
            except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
                row = verification_row(
                    host,
                    "",
                    "",
                    connection_status="UNREACHABLE",
                    error=f"{type(exc).__name__}: verification worker failed",
                )
            rows.append(row)
            log.info(
                "[%s] connection=%s status=%s consistency=%s parsed=%s",
                host,
                row["connection_status"],
                row["verification_status"],
                row["consistency"],
                all(
                    row.get(key) == "true"
                    for key in (
                        "snmpv1_confident",
                        "snmpv3_users_confident",
                        "snmpv3_access_confident",
                    )
                ),
            )
            print(
                f"{host}: {row['verification_status']} "
                f"(connection={row['connection_status']}, consistency={row['consistency']})",
                flush=True,
            )
    write_verification_csv(output_path, rows)
    print(f"Completed {len(rows)}/{len(devices)} device(s); CSV: {output_path}; log: {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
