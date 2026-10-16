"""Strict parsers and read-only verification helpers for APC SNMP CLI output."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ANSI_RE = re.compile(r"\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\))")
PROMPT_RE = re.compile(r"(?:[A-Za-z0-9_.-]+)?\s*>\s*$")
TRUNCATION_RE = re.compile(r"(?:\.\.\.|-{1,2})\s*$")

V1_FIELDS = {
    "community": re.compile(r"^(?:SNMP\s*)?Community\s*:\s*(.*)$", re.I),
    "access": re.compile(r"^(?:Access(?:\s+Type)?)\s*:\s*(.*)$", re.I),
    "address": re.compile(
        r"^(?:NMS\s*IP(?:/Host\s*Name)?|Address|Host\s*Name)\s*:\s*(.*)$", re.I
    ),
}
V3_USER_FIELDS = {
    "username": re.compile(r"^(?:User\s*Name|Username)\s*:\s*(.*)$", re.I),
    "authentication": re.compile(
        r"^(?:Authentication(?:\s+Protocol)?|Auth(?:entication)?)\s*:\s*(.*)$", re.I
    ),
    "privacy": re.compile(
        r"^(?:Privacy(?:\s+Protocol)?|Encryption(?:\s+Protocol)?)\s*:\s*(.*)$", re.I
    ),
}
V3_ACCESS_FIELDS = {
    "username": re.compile(
        r"^(?:Access\s+User(?:\s+Profile)?(?:\s+Name)?|User\s*Name|Username)\s*:\s*(.*)$",
        re.I,
    ),
    "access": re.compile(r"^(?:Access|Status)\s*:\s*(.*)$", re.I),
    "address": re.compile(
        r"^(?:NMS\s*IP(?:/Host\s*Name)?|Address|Host\s*Name)\s*:\s*(.*)$", re.I
    ),
}


@dataclass(frozen=True)
class ParsedTable:
    entries: dict[int, dict[str, str]]
    confident: bool
    error: str = ""


@dataclass(frozen=True)
class DeviceVerification:
    values: dict[str, Any]
    connection_status: str
    consistency: str
    verification_status: str
    parsed_confidently: bool
    firmware: str = ""
    error: str = ""


def clean_cli_text(text: str) -> str:
    text = ANSI_RE.sub("", str(text or "")).replace("\r\n", "\n").replace("\r", "\n")
    output: list[str] = []
    for char in text:
        if char == "\x08":
            if output:
                output.pop()
        elif char != "\x00":
            output.append(char)
    return "".join(output)


def normalize(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).casefold()


def _heading_index(line: str, kind: str) -> int | None:
    if kind == "user":
        pattern = r"^(?:SNMPv3\s+)?User\s+Profile\s*(?:#\s*)?([1-4])\s*:?\s*$"
    elif kind == "access":
        pattern = (
            r"^(?:(?:SNMPv[13])\s+)?Access\s+Control"
            r"(?:\s+Entry)?\s*(?:#\s*)?([1-4])\s*:?\s*$"
        )
    elif kind == "v1":
        pattern = (
            r"^(?:(?:SNMPv1)\s+)?(?:Access\s+Control(?:\s+Entry)?|Entry|Profile)"
            r"\s*(?:#\s*)?([1-4])\s*:?\s*$"
        )
    else:
        raise ValueError(f"Unknown table kind: {kind}")
    match = re.fullmatch(pattern, line.strip(), re.I)
    return int(match.group(1)) if match else None


def _parse_blocks(text: str, kind: str, field_patterns: dict[str, re.Pattern[str]]) -> ParsedTable:
    lines = clean_cli_text(text).splitlines()
    blocks: dict[int, dict[str, str]] = {}
    duplicates: set[int] = set()
    current: int | None = None
    pending_field: str | None = None
    previous_field: str | None = None
    for raw_line in lines:
        line = raw_line.strip()
        index = _heading_index(line, kind)
        if index is not None:
            if index in blocks:
                duplicates.add(index)
            blocks.setdefault(index, {})
            current = index
            pending_field = None
            previous_field = None
            continue
        if current is None:
            continue
        matched = False
        for key, pattern in field_patterns.items():
            match = pattern.fullmatch(line)
            if match:
                value = match.group(1).strip()
                if value:
                    blocks[current][key] = value
                    pending_field = None
                    previous_field = key
                else:
                    pending_field = key
                    previous_field = None
                matched = True
                break
        if matched:
            continue
        if pending_field and line and not _is_table_heading(line):
            key = pending_field
            blocks[current][key] = line
            pending_field = None
            previous_field = key
            continue
        if (
            raw_line[:1].isspace()
            and previous_field
            and line
            and not _is_table_heading(line)
        ):
            blocks[current][previous_field] += f" {line}"
        else:
            previous_field = None

    required = set(field_patterns)
    complete = all(
        index in blocks and required.issubset(blocks[index]) for index in range(1, 5)
    )
    if duplicates:
        return ParsedTable(blocks, False, f"duplicate table entries: {sorted(duplicates)}")
    if not complete:
        missing = [
            f"{index}:{','.join(sorted(required - set(blocks.get(index, {}))))}"
            for index in range(1, 5)
            if not required.issubset(blocks.get(index, {}))
        ]
        return ParsedTable(blocks, False, "incomplete entries " + "; ".join(missing))
    if TRUNCATION_RE.search(lines[-1].strip()) if lines else True:
        return ParsedTable(blocks, False, "output may be truncated")
    return ParsedTable(blocks, True)


def _is_table_heading(line: str) -> bool:
    return bool(
        re.fullmatch(
            r"(?:(?:SNMPv[13])\s+)?(?:User\s+Profiles?|Access\s+Control(?:\s+Entries)?|"
            r"SNMPv[13])\s*:?",
            line.strip(),
            re.I,
        )
        or _heading_index(line, "user") is not None
        or _heading_index(line, "access") is not None
        or _heading_index(line, "v1") is not None
    )


def parse_v1_output(text: str, *, partial: bool = False) -> ParsedTable:
    parsed = _parse_blocks(text, "v1", V1_FIELDS)
    if partial:
        return ParsedTable(parsed.entries, False, "command response was partial")
    return parsed


def _split_v3_sections(text: str) -> tuple[str, str] | None:
    lines = clean_cli_text(text).splitlines()
    user_heading: int | None = None
    access_heading: int | None = None
    for index, raw_line in enumerate(lines):
        line = raw_line.strip()
        if re.fullmatch(r"(?:SNMPv3\s+)?User\s+Profiles?\s*:?", line, re.I):
            user_heading = index
        elif re.fullmatch(
            r"(?:SNMPv3\s+)?Access\s+Control(?:\s+Entries)?\s*:?", line, re.I
        ):
            access_heading = index
            break
    if user_heading is None or access_heading is None or access_heading <= user_heading:
        return None
    return "\n".join(lines[user_heading + 1 : access_heading]), "\n".join(
        lines[access_heading + 1 :]
    )


def parse_v3_output(text: str, *, partial: bool = False) -> tuple[ParsedTable, ParsedTable]:
    sections = _split_v3_sections(text)
    if sections is None:
        unknown = ParsedTable({}, False, "separate user-profile and access-control headings not found")
        return unknown, unknown
    users = _parse_blocks(sections[0], "user", V3_USER_FIELDS)
    access = _parse_blocks(sections[1], "access", V3_ACCESS_FIELDS)
    if partial:
        reason = "command response was partial"
        users = ParsedTable(users.entries, False, reason)
        access = ParsedTable(access.entries, False, reason)
    return users, access


def confirmed_blank_v1(table: ParsedTable, index: int) -> bool:
    entry = table.entries.get(index, {})
    return (
        table.confident
        and normalize(entry.get("community")) == "public"
        and normalize(entry.get("access")) in {"disabled", "disable"}
        and normalize(entry.get("address")) == "0.0.0.0"
    )


def confirmed_blank_v3_user(table: ParsedTable, index: int) -> bool:
    entry = table.entries.get(index, {})
    return (
        index in range(2, 5)
        and table.confident
        and normalize(entry.get("username")) == f"apc snmp profile{index}"
        and normalize(entry.get("authentication")) == "none"
        and normalize(entry.get("privacy")) == "none"
    )


def confirmed_blank_v3_access(table: ParsedTable, index: int) -> bool:
    entry = table.entries.get(index, {})
    return (
        index in range(2, 5)
        and table.confident
        and normalize(entry.get("username")) == f"apc snmp profile{index}"
        and normalize(entry.get("access")) in {"disabled", "disable"}
        and normalize(entry.get("address")) == "0.0.0.0"
    )


def extract_firmware(*outputs: str) -> str:
    pattern = re.compile(
        r"^\s*(?:AOS|UPS|NMC|Firmware(?:\s+Version)?)\s*[:=]\s*(.*?)\s*$", re.I | re.M
    )
    matches = []
    for output in outputs:
        matches.extend(match.group(1).strip() for match in pattern.finditer(clean_cli_text(output)))
    return "; ".join(dict.fromkeys(matches))


def verify_readbacks(
    v1_output: str,
    v3_output: str,
    *,
    v1_partial: bool = False,
    v3_partial: bool = False,
) -> tuple[dict[str, ParsedTable], tuple[str, str, bool, str]]:
    v1 = parse_v1_output(v1_output, partial=v1_partial)
    users, access = parse_v3_output(v3_output, partial=v3_partial)
    consistency = "UNKNOWN"
    if users.confident and access.confident:
        consistent = all(
            normalize(users.entries[index]["username"])
            == normalize(access.entries[index]["username"])
            for index in range(1, 5)
        )
        consistency = "CONSISTENT" if consistent else "INCONSISTENT"
    parsed = v1.confident and users.confident and access.confident
    if consistency == "INCONSISTENT":
        status = "MISMATCH"
    elif parsed and consistency == "CONSISTENT":
        status = "VERIFIED"
    else:
        status = "UNKNOWN"
    errors = "; ".join(
        reason
        for reason in (v1.error, users.error, access.error)
        if reason
    )
    return {"snmpv1": v1, "snmpv3_users": users, "snmpv3_access": access}, (
        consistency,
        status,
        parsed,
        errors,
    )


def verification_row(
    host: str,
    v1_output: str,
    v3_output: str,
    *,
    connection_status: str = "CONNECTED",
    v1_partial: bool = False,
    v3_partial: bool = False,
    error: str = "",
) -> dict[str, str]:
    row = {
        "device_ip": host,
        "connection_status": connection_status,
        "firmware": extract_firmware(v1_output, v3_output),
        "snmpv1_confident": "false",
        "snmpv3_users_confident": "false",
        "snmpv3_access_confident": "false",
        "consistency": "UNKNOWN",
        "verification_status": "UNKNOWN",
        "error": error,
    }
    if connection_status != "CONNECTED":
        row["verification_status"] = "UNREACHABLE"
        return row
    tables, (consistency, status, _, parse_error) = verify_readbacks(
        v1_output, v3_output, v1_partial=v1_partial, v3_partial=v3_partial
    )
    row["consistency"] = consistency
    row["verification_status"] = status
    row["error"] = "; ".join(part for part in (error, parse_error) if part)
    for name, table in tables.items():
        key = {
            "snmpv1": "snmpv1_confident",
            "snmpv3_users": "snmpv3_users_confident",
            "snmpv3_access": "snmpv3_access_confident",
        }[name]
        row[key] = str(table.confident).lower()
        for index in range(1, 5):
            values = table.entries.get(index, {})
            for field, value in values.items():
                # Communities are credentials and must never be exported verbatim.
                safe_value = "<REDACTED>" if name == "snmpv1" and field == "community" and value else value
                row[f"{name}_{index}_{field}"] = safe_value
            if name == "snmpv3_users":
                row[f"{name}_{index}_auth_passphrase"] = "<NOT READABLE>"
                row[f"{name}_{index}_privacy_passphrase"] = "<NOT READABLE>"
    return row


def verification_csv_columns() -> list[str]:
    columns = [
        "device_ip",
        "connection_status",
        "firmware",
        "snmpv1_confident",
    ]
    for index in range(1, 5):
        columns.extend(
            f"snmpv1_{index}_{field}" for field in ("community", "access", "address")
        )
    columns.append("snmpv3_users_confident")
    for index in range(1, 5):
        columns.extend(
            f"snmpv3_users_{index}_{field}"
            for field in ("username", "authentication", "privacy", "auth_passphrase", "privacy_passphrase")
        )
    columns.append("snmpv3_access_confident")
    for index in range(1, 5):
        columns.extend(
            f"snmpv3_access_{index}_{field}" for field in ("username", "access", "address")
        )
    columns.extend(("consistency", "verification_status", "error"))
    return columns


def write_verification_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=verification_csv_columns())
        writer.writeheader()
        writer.writerows(rows)
