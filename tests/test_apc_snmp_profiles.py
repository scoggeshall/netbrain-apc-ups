"""Sanitized APC CLI-shaped examples for SNMP profile verification."""

from apc_snmp_profiles import (
    ParsedTable,
    build_v1_command,
    build_v3_access_command,
    build_v3_user_command,
    classify_write_outcome,
    confirmed_blank_v1,
    confirmed_blank_v3_access,
    confirmed_blank_v3_user,
    parse_v1_output,
    parse_v3_output,
    verification_row,
    verify_readbacks,
    write_verification_csv,
)
from configure_snmp_blank_profiles_only_verified_workers import (
    build_blank_slot_commands,
    safe_readback_summary,
    validate_verification_report,
)

V1_OUTPUT = """\
SNMP Access Control
Access Control Entry #1
 Community: <community-redacted>
 Access: read
 NMS IP/Host Name: 10.10.9.20
Access Control Entry #2
 Community: public
 Access: disable
 NMS IP/Host Name: 0.0.0.0
Access Control Entry #3
 Community: private
 Access: read
 NMS IP/Host Name: 161.243.255.255
Access Control Entry #4
 Community: public
 Access: disabled
 NMS IP/Host Name: 10.10.9.255
"""

V3_OUTPUT = """\
SNMPv3 User Profiles
User Profile #1
 User Name: operator1
 Authentication Protocol: SHA
 Privacy Protocol: AES
User Profile #2
 User Name: apc snmp profile2
 Authentication Protocol: none
 Privacy Protocol: none
User Profile #3
 User Name: operator3
 Authentication Protocol: SHA
 Privacy Protocol: AES
User Profile #4
 User Name: apc snmp profile4
 Authentication Protocol: none
 Privacy Protocol: none
SNMPv3 Access Control Entries
Access Control Entry #1
 User Name: operator1
 Access: enabled
 NMS IP/Host Name: 10.10.9.20
Access Control Entry #2
 User Name: apc snmp profile2
 Access: disabled
 NMS IP/Host Name: 0.0.0.0
Access Control Entry #3
 User Name: operator3
 Access: enabled
 NMS IP/Host Name: 161.243.255.255
Access Control Entry #4
 User Name: apc snmp profile4
 Access: disabled
 NMS IP/Host Name: 10.10.9.255
"""


def test_parses_four_snmpv1_access_entries_and_preserves_wildcard_address() -> None:
    parsed = parse_v1_output(V1_OUTPUT)

    assert parsed.confident
    assert parsed.entries[1]["community"] == "<community-redacted>"
    assert parsed.entries[3]["address"] == "161.243.255.255"
    assert not confirmed_blank_v1(parsed, 1)
    assert confirmed_blank_v1(parsed, 2)
    assert not confirmed_blank_v1(parsed, 3)
    assert not confirmed_blank_v1(parsed, 4)


def test_parses_separate_snmpv3_user_and_access_tables() -> None:
    users, access = parse_v3_output(V3_OUTPUT)

    assert users.confident
    assert access.confident
    assert users.entries[3]["username"] == "operator3"
    assert access.entries[3]["address"] == "161.243.255.255"
    assert confirmed_blank_v3_user(users, 2)
    assert not confirmed_blank_v3_user(users, 1)
    assert confirmed_blank_v3_access(access, 2)
    assert not confirmed_blank_v3_access(access, 3)
    assert not confirmed_blank_v3_access(access, 4)


def test_accepts_whitespace_and_values_wrapped_to_indented_next_line() -> None:
    output = V3_OUTPUT.replace(
        " User Name: operator3",
        " User Name:\n   operator3",
    ).replace(
        " NMS IP/Host Name: 161.243.255.255",
        " NMS IP/Host Name:\n   161.243.255.255",
    )
    users, access = parse_v3_output(output)

    assert users.confident
    assert access.confident
    assert users.entries[3]["username"] == "operator3"
    assert access.entries[3]["address"] == "161.243.255.255"


def test_partial_or_truncated_output_is_not_confident() -> None:
    partial = parse_v1_output(V1_OUTPUT, partial=True)
    truncated = parse_v1_output(V1_OUTPUT.rsplit("\n", 1)[0] + "\n -")

    assert not partial.confident
    assert "partial" in partial.error
    assert not truncated.confident
    assert "truncated" in truncated.error
    assert not confirmed_blank_v1(partial, 2)


def test_partial_success_response_is_ambiguous_and_never_confirmed() -> None:
    assert classify_write_outcome("E000: Success", partial=True) == "ambiguous"
    assert classify_write_outcome("E000: Success", partial=False) == "success"
    assert classify_write_outcome("", partial=False) == "ambiguous"


def test_unrecognized_or_missing_table_formats_are_unknown() -> None:
    users, access = parse_v3_output("SNMPv3\nProfile 2: unknown format")
    incomplete = parse_v1_output("Access Control Entry #1\nCommunity: public")

    assert not users.confident
    assert not access.confident
    assert not incomplete.confident
    assert not confirmed_blank_v1(incomplete, 1)


def test_unrecognized_field_values_are_unknown_instead_of_assumed_valid() -> None:
    unknown_access = parse_v1_output(V1_OUTPUT.replace("Access: read", "Access: maybe"))
    unknown_protocol, _ = parse_v3_output(
        V3_OUTPUT.replace("Authentication Protocol: SHA", "Authentication Protocol: SHA-256")
    )

    assert not unknown_access.confident
    assert not unknown_protocol.confident


def test_username_mismatch_is_reported_without_loosening_comparison() -> None:
    mismatch = V3_OUTPUT.replace(
        " User Name: operator3\n Access: enabled",
        " User Name: other-user\n Access: enabled",
    )
    tables, (consistency, status, parsed, _) = verify_readbacks(V1_OUTPUT, mismatch)

    assert parsed
    assert consistency == "INCONSISTENT"
    assert status == "MISMATCH"
    assert tables["snmpv3_access"].entries[3]["username"] == "other-user"


def test_usernames_are_compared_case_sensitively() -> None:
    changed_case = V3_OUTPUT.replace(
        " User Name: operator3\n Access: enabled",
        " User Name: Operator3\n Access: enabled",
    )
    _, (consistency, status, _, _) = verify_readbacks(V1_OUTPUT, changed_case)

    assert consistency == "INCONSISTENT"
    assert status == "MISMATCH"


def test_inconsistent_user_and_access_entries_are_not_reported_verified() -> None:
    row = verification_row(
        "192.0.2.10",
        V1_OUTPUT,
        V3_OUTPUT.replace(
            " User Name: operator3\n Access: enabled",
            " User Name: different\n Access: enabled",
        ),
    )

    assert row["consistency"] == "INCONSISTENT"
    assert row["verification_status"] == "MISMATCH"


def test_ssh_timeout_or_unrecognized_state_never_confirms_blank_slots() -> None:
    unreachable = verification_row(
        "192.0.2.11", "", "", connection_status="UNREACHABLE", error="TimeoutError"
    )
    unknown = parse_v1_output("Access Control Entry #2\nCommunity: public")

    assert unreachable["verification_status"] == "UNREACHABLE"
    assert not confirmed_blank_v1(unknown, 2)
    assert not confirmed_blank_v3_user(ParsedTable({}, False, "unknown"), 2)


def test_communities_are_redacted_in_csv_row() -> None:
    row = verification_row("192.0.2.12", V1_OUTPUT, V3_OUTPUT)

    assert row["snmpv1_1_community"] == "<REDACTED>"
    assert row["snmpv1_2_community"] == "<REDACTED>"
    assert row["snmpv3_users_2_auth_passphrase"] == "<NOT READABLE>"


def test_csv_export_includes_firmware_and_never_exports_community(tmp_path) -> None:
    row = verification_row("192.0.2.12", "AOS: 7.2.1\n" + V1_OUTPUT, V3_OUTPUT)
    path = tmp_path / "profiles.csv"

    write_verification_csv(path, [row])
    csv_text = path.read_text(encoding="utf-8-sig")

    assert "7.2.1" in csv_text
    assert "<REDACTED>" in csv_text
    assert "<community-redacted>" not in csv_text


def test_configuration_readback_log_redacts_all_community_values() -> None:
    summary = safe_readback_summary(V1_OUTPUT, "snmp", partial=False)

    assert "<REDACTED>" in summary
    assert "<community-redacted>" not in summary
    assert "private" not in summary


def test_command_builder_preserves_exact_profile_index_mapping() -> None:
    for index in (2, 3, 4):
        user_command = build_v3_user_command(
            index, "operator", "sha", "aes", "auth-secret", "privacy-secret"
        )
        access_command = build_v3_access_command(index, "operator", "192.0.2.20")

        assert f"-u{index}" in user_command
        assert f"-ap{index} sha" in user_command
        assert f"-pp{index} aes" in user_command
        assert f"-a{index} " in user_command
        assert f"-c{index} " in user_command
        assert f"-ac{index}" in access_command
        assert f"-au{index}" in access_command
        assert f"-n{index} 192.0.2.20" in access_command
    assert build_v1_command(3, "community", "read", "192.0.2.30") == (
        'snmp -c3 "community" -a3 read -n3 192.0.2.30'
    )


def test_command_builders_reject_profile_one_and_unsafe_arguments() -> None:
    import pytest

    with pytest.raises(ValueError):
        build_v3_user_command(1, "operator", "sha", "aes", "auth-secret", "privacy-secret")
    with pytest.raises(ValueError):
        build_v3_access_command(1, "operator", "192.0.2.20")
    with pytest.raises(ValueError):
        build_v3_user_command(2, 'bad"; snmpv3 -S enable', "sha", "aes", "x", "y")


def test_configuration_builder_emits_no_write_for_partial_or_unknown_state() -> None:
    v1 = parse_v1_output(V1_OUTPUT, partial=True)
    users, access = parse_v3_output(V3_OUTPUT, partial=True)
    config = {
        "snmpv1": {
            "profile2": {
                "enabled": True,
                "nms_ip": "192.0.2.30",
                "community": "community-secret",
                "access": "read",
            }
        }
    }

    commands = build_blank_slot_commands(config, (v1, users, access), "192.0.2.1")
    unrecognized = parse_v1_output(V1_OUTPUT.replace("Access: read", "Access: maybe"))
    valid_users, valid_access = parse_v3_output(V3_OUTPUT)
    unrecognized_commands = build_blank_slot_commands(
        config, (unrecognized, valid_users, valid_access), "192.0.2.1"
    )

    assert commands == []
    assert unrecognized_commands == []


def test_configuration_builder_dry_syntax_gate_withholds_unverified_v3_writes() -> None:
    v1 = parse_v1_output(V1_OUTPUT)
    users, access = parse_v3_output(V3_OUTPUT)
    config = {
        "snmpv3": {
            "profile2": {
                "enabled": True,
                "username": "operator2",
                "nms_ip": "192.0.2.20",
                "auth_passphrase": "auth-secret",
                "privacy_passphrase": "privacy-secret",
                "auth_protocol": "sha",
                "privacy_protocol": "aes",
            }
        }
    }

    commands = build_blank_slot_commands(config, (v1, users, access), "192.0.2.1")

    assert commands == []


def test_existing_matching_user_can_receive_independent_blank_access_entry() -> None:
    v1 = parse_v1_output(V1_OUTPUT)
    configured_user_output = V3_OUTPUT.replace(
        "User Name: apc snmp profile2\n Authentication Protocol: none\n Privacy Protocol: none",
        "User Name: operator2\n Authentication Protocol: SHA\n Privacy Protocol: AES",
    )
    users, access = parse_v3_output(configured_user_output)
    config = {
        "snmpv3": {
            "profile2": {
                "enabled": True,
                "username": "operator2",
                "nms_ip": "192.0.2.20",
                "auth_passphrase": "auth-secret",
                "privacy_passphrase": "privacy-secret",
                "auth_protocol": "sha",
                "privacy_protocol": "aes",
            }
        }
    }

    commands = build_blank_slot_commands(config, (v1, users, access), "192.0.2.1")

    assert len(commands) == 1
    assert commands[0][3] == ("v3_access", 2)
    assert commands[0][1] == ('snmpv3 -ac2 enable -au2 "operator2" -n2 192.0.2.20')


def test_index_headings_are_parsed_only_inside_distinct_tables() -> None:
    output = V3_OUTPUT
    for index in range(1, 5):
        output = output.replace(f"User Profile #{index}", f"Index: {index}")
        output = output.replace(f"Access Control Entry #{index}", f"Index: {index}")
    users, access = parse_v3_output(output)

    assert users.confident
    assert access.confident
    assert users.entries[2]["username"] == "apc snmp profile2"


def test_broader_write_report_requires_every_device_to_be_verified(tmp_path) -> None:
    import pytest

    report = tmp_path / "verification.csv"
    report.write_text(
        "device_ip,verification_status\n192.0.2.1,VERIFIED\n192.0.2.2,UNKNOWN\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="not verified"):
        validate_verification_report(report, ["192.0.2.1", "192.0.2.2"])
