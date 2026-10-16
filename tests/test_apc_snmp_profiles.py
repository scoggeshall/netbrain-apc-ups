"""Sanitized APC CLI-shaped examples for SNMP profile verification."""

from apc_snmp_profiles import (
    ParsedTable,
    build_v1_command,
    build_v3_access_command,
    build_v3_user_command,
    confirmed_blank_v1,
    confirmed_blank_v3_access,
    confirmed_blank_v3_user,
    parse_v1_output,
    parse_v3_output,
    verification_row,
    verify_readbacks,
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


def test_unrecognized_or_missing_table_formats_are_unknown() -> None:
    users, access = parse_v3_output("SNMPv3\nProfile 2: unknown format")
    incomplete = parse_v1_output("Access Control Entry #1\nCommunity: public")

    assert not users.confident
    assert not access.confident
    assert not incomplete.confident
    assert not confirmed_blank_v1(incomplete, 1)


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
