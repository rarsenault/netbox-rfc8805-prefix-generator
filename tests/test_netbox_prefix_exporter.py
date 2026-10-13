import csv
from datetime import datetime, timezone
import ipaddress
import sys
from unittest.mock import Mock, patch

import pytest
import requests

import netbox_prefix_exporter
from netbox_prefix_exporter import (
    _subtract_blacklist,
    fetch_prefixes,
    fetch_regions,
    main,
    parse_blocklist,
    split_by_location,
    write_aggregated_geofeed,
)


REGIONS = [
    {"id": 1, "name": "CA", "parent": None},
    {"id": 2, "name": "CA-ON", "parent": {"id": 1}},
    {"id": 3, "name": "Toronto", "parent": {"id": 2}},
    {"id": 4, "name": "Ottawa", "parent": {"id": 2}},
]


def region_prefix(prefix, scope_id):
    return {"prefix": prefix, "scope_type": "dcim.region", "scope_id": scope_id}


# --- Fetching -------------------------------------------------------------


def test_fetch_prefixes_filters_by_region_scope_and_follows_pagination():
    first_page = Mock()
    first_page.json.return_value = {
        "results": [{"prefix": "192.0.2.0/24"}],
        "next": "https://netbox.example.com/api/ipam/prefixes/?offset=1",
    }
    second_page = Mock()
    second_page.json.return_value = {
        "results": [{"prefix": "198.51.100.0/24"}],
        "next": None,
    }

    with patch("netbox_prefix_exporter.requests.Session") as session_type:
        session = session_type.return_value.__enter__.return_value
        session.get.side_effect = [first_page, second_page]

        prefixes = fetch_prefixes("https://netbox.example.com", "secret")

    assert [item["prefix"] for item in prefixes] == ["192.0.2.0/24", "198.51.100.0/24"]
    assert session.get.call_args_list[0].kwargs["params"] == {"scope_type": "dcim.region"}
    assert session.get.call_args_list[1].kwargs["params"] is None
    assert session.get.call_args_list[0].kwargs["headers"]["Authorization"] == "Token secret"
    assert (
        session.get.call_args_list[1].args[0]
        == "https://netbox.example.com/api/ipam/prefixes/?offset=1"
    )


def test_fetch_prefixes_filters_by_optional_tag():
    response = Mock()
    response.json.return_value = {"results": [{"prefix": "192.0.2.0/24"}], "next": None}

    with patch("netbox_prefix_exporter.requests.Session") as session_type:
        session = session_type.return_value.__enter__.return_value
        session.get.return_value = response

        prefixes = fetch_prefixes("https://netbox.example.com", "secret", "geofeed")

    assert prefixes == [{"prefix": "192.0.2.0/24"}]
    assert session.get.call_args.kwargs["params"] == {
        "scope_type": "dcim.region",
        "tag": "geofeed",
    }


def test_fetch_regions_follows_pagination():
    first_page = Mock()
    first_page.json.return_value = {
        "results": [{"id": 1, "name": "CA"}],
        "next": "https://netbox.example.com/api/dcim/regions/?offset=1",
    }
    second_page = Mock()
    second_page.json.return_value = {"results": [{"id": 2, "name": "CA-ON"}], "next": None}

    with patch("netbox_prefix_exporter.requests.Session") as session_type:
        session = session_type.return_value.__enter__.return_value
        session.get.side_effect = [first_page, second_page]

        regions = fetch_regions("https://netbox.example.com", "secret")

    assert [region["name"] for region in regions] == ["CA", "CA-ON"]
    assert session.get.call_args_list[1].kwargs["params"] is None


def test_fetch_results_retries_transient_errors_and_only_uses_get():
    response = Mock()
    response.json.return_value = {"results": [], "next": None}

    with patch("netbox_prefix_exporter.requests.Session") as session_type:
        session = session_type.return_value.__enter__.return_value
        session.get.return_value = response

        fetch_regions("https://netbox.example.com", "secret")

    mounted = {call.args[0]: call.args[1] for call in session.mount.call_args_list}
    assert set(mounted) == {"https://", "http://"}
    retry = mounted["https://"].max_retries
    assert retry.total == 3
    assert 502 in retry.status_forcelist
    assert set(retry.allowed_methods) == {"GET"}
    # The exporter must stay read-only.
    session.post.assert_not_called()
    session.put.assert_not_called()
    session.patch.assert_not_called()
    session.delete.assert_not_called()


# --- Blocklist parsing ----------------------------------------------------


def test_parse_blocklist_handles_whitespace_blanks_and_both_ip_versions():
    assert parse_blocklist(" 10.0.0.0/8 , ,2001:db8::/32,") == [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("2001:db8::/32"),
    ]


def test_parse_blocklist_empty_string_disables_exclusions():
    assert parse_blocklist("") == []
    assert parse_blocklist("  ,  ") == []


def test_parse_blocklist_accepts_host_bits_like_the_rest_of_the_exporter():
    assert parse_blocklist("192.0.2.5/24") == [ipaddress.ip_network("192.0.2.0/24")]


def test_parse_blocklist_names_the_bad_entry():
    with pytest.raises(ValueError, match=r"'10.0.0.0/33'.*NETBOX_PREFIX_BLOCKLIST"):
        parse_blocklist("192.0.2.0/24,10.0.0.0/33")


# --- Location resolution --------------------------------------------------


def test_split_by_location_separates_unresolved_prefixes():
    regions = REGIONS + [
        {"id": 5, "name": "Orphan", "parent": None},  # no province or country
        {"id": 6, "name": "CA-PE", "parent": {"id": 1}},
        {"id": 7, "name": "Charlottetown", "parent": {"id": 6}},
    ]
    good = region_prefix("192.0.2.0/24", 3)
    orphan = region_prefix("198.51.100.0/24", 5)
    unknown_region = region_prefix("203.0.113.0/24", 999)
    no_scope = {"prefix": "203.0.114.0/24", "scope_type": None, "scope_id": None}
    wrong_scope_type = {"prefix": "203.0.115.0/24", "scope_type": "dcim.site", "scope_id": 3}
    # Charlottetown -> CA-PE -> CA is a complete hierarchy, so it is resolved.
    resolved_other = region_prefix("203.0.116.0/24", 7)

    located, unresolved = split_by_location(
        [good, orphan, unknown_region, no_scope, wrong_scope_type, resolved_other],
        regions,
    )

    assert located == [good, resolved_other]
    assert unresolved == [orphan, unknown_region, no_scope, wrong_scope_type]


def test_split_by_location_flags_city_whose_province_has_no_country():
    regions = [
        {"id": 2, "name": "CA-ON", "parent": None},
        {"id": 3, "name": "Toronto", "parent": {"id": 2}},
    ]
    prefix = region_prefix("192.0.2.0/24", 3)

    located, unresolved = split_by_location([prefix], regions)

    assert located == []
    assert unresolved == [prefix]


# --- Blocklist subtraction ------------------------------------------------


def test_subtract_blacklist_drops_network_fully_inside_blocked_range():
    network = ipaddress.ip_network("192.0.2.128/25")

    assert _subtract_blacklist(network, [ipaddress.ip_network("192.0.2.0/24")]) == []


def test_subtract_blacklist_ignores_other_ip_version_and_non_overlapping_ranges():
    network = ipaddress.ip_network("192.0.2.0/24")
    blacklist = [
        ipaddress.ip_network("2001:db8::/32"),
        ipaddress.ip_network("198.51.100.0/24"),
    ]

    assert _subtract_blacklist(network, blacklist) == [network]


def test_subtract_blacklist_handles_multiple_overlapping_entries():
    network = ipaddress.ip_network("192.0.2.0/24")
    blacklist = [
        ipaddress.ip_network("192.0.2.0/26"),
        ipaddress.ip_network("192.0.2.192/26"),
    ]

    assert sorted(_subtract_blacklist(network, blacklist)) == [
        ipaddress.ip_network("192.0.2.64/26"),
        ipaddress.ip_network("192.0.2.128/26"),
    ]


# --- Geofeed output -------------------------------------------------------


def test_write_aggregated_geofeed_collapses_only_matching_locations(tmp_path):
    output = tmp_path / "geofeed-aggregated.csv"
    generated_at = datetime(2024, 8, 30, 4, 18, 56, tzinfo=timezone.utc)
    exported_count = write_aggregated_geofeed(
        [
            region_prefix("192.0.2.0/25", 3),
            region_prefix("192.0.2.128/25", 3),
            region_prefix("198.51.100.0/24", 4),
            region_prefix("2001:db8::/33", 3),
            region_prefix("2001:db8:8000::/33", 3),
        ],
        REGIONS,
        output,
        generated_at,
    )

    lines = output.read_text(encoding="utf-8").splitlines()
    rows = list(csv.reader(lines[2:]))

    assert lines[:2] == [
        "# Aggregated RFC8805 geofeed generated August 30 2024 - 00:18:56 (Eastern Daylight Time)",
        "# ip_prefix,alpha2code,region,city,postal_code",
    ]
    assert rows == [
        ["192.0.2.0/24", "CA", "CA-ON", "Toronto", ""],
        ["198.51.100.0/24", "CA", "CA-ON", "Ottawa", ""],
        ["2001:db8::/32", "CA", "CA-ON", "Toronto", ""],
    ]
    assert exported_count == len(rows) == 3
    assert not (tmp_path / "geofeed.csv").exists()


def test_write_aggregated_geofeed_uses_standard_time_header_in_winter(tmp_path):
    output = tmp_path / "geofeed-aggregated.csv"
    generated_at = datetime(2024, 1, 15, 5, 30, 0, tzinfo=timezone.utc)

    write_aggregated_geofeed([region_prefix("192.0.2.0/24", 3)], REGIONS, output, generated_at)

    first_line = output.read_text(encoding="utf-8").splitlines()[0]
    assert first_line == (
        "# Aggregated RFC8805 geofeed generated January 15 2024 - 00:30:00 "
        "(Eastern Standard Time)"
    )


def test_write_aggregated_geofeed_keeps_ipv4_and_ipv6_separate_in_one_location(tmp_path):
    output = tmp_path / "geofeed-aggregated.csv"

    # Both prefixes share the same city; mixing versions in collapse_addresses
    # would raise TypeError if they were not grouped separately.
    exported_count = write_aggregated_geofeed(
        [region_prefix("2001:db8::/32", 3), region_prefix("192.0.2.0/24", 3)],
        REGIONS,
        output,
    )

    rows = list(csv.reader(output.read_text(encoding="utf-8").splitlines()[2:]))
    assert rows == [
        ["192.0.2.0/24", "CA", "CA-ON", "Toronto", ""],
        ["2001:db8::/32", "CA", "CA-ON", "Toronto", ""],
    ]
    assert exported_count == 2


def test_write_aggregated_geofeed_subtracts_blacklisted_address_ranges(tmp_path):
    output = tmp_path / "geofeed-aggregated.csv"
    regions = REGIONS[:3]

    exported_count = write_aggregated_geofeed(
        [
            region_prefix("192.0.2.0/24", 3),
            region_prefix("198.51.100.0/24", 3),
            region_prefix("2001:db8::/32", 3),
        ],
        regions,
        output,
        blacklist=[
            ipaddress.ip_network("192.0.2.64/26"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("2001:db8::/33"),
        ],
    )

    rows = list(csv.reader(output.read_text(encoding="utf-8").splitlines()[2:]))

    assert rows == [
        ["192.0.2.0/26", "CA", "CA-ON", "Toronto", ""],
        ["192.0.2.128/25", "CA", "CA-ON", "Toronto", ""],
        ["2001:db8:8000::/33", "CA", "CA-ON", "Toronto", ""],
    ]
    assert exported_count == len(rows) == 3


# --- main() ---------------------------------------------------------------


@pytest.fixture
def cli(monkeypatch, tmp_path):
    """Run main() with a fake environment, no .env file, and no network."""
    output = tmp_path / "out.csv"
    monkeypatch.setattr(netbox_prefix_exporter, "load_dotenv", lambda: None)
    for name in ("NETBOX_URL", "NETBOX_TOKEN", "NETBOX_TAG", "NETBOX_PREFIX_BLOCKLIST"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NETBOX_URL", "https://netbox.example.com")
    monkeypatch.setenv("NETBOX_TOKEN", "secret")
    monkeypatch.setattr(sys, "argv", ["netbox_prefix_exporter.py", "--output", str(output)])
    return output


def test_main_exports_resolved_prefixes_and_warns_about_unresolved(cli, capsys):
    prefixes = [
        region_prefix("192.0.2.0/25", 3),
        region_prefix("192.0.2.128/25", 3),
        region_prefix("198.51.100.0/24", 999),  # Region does not exist
    ]
    with patch.object(netbox_prefix_exporter, "fetch_prefixes", return_value=prefixes), \
            patch.object(netbox_prefix_exporter, "fetch_regions", return_value=REGIONS):
        assert main() == 0

    rows = list(csv.reader(cli.read_text(encoding="utf-8").splitlines()[2:]))
    assert rows == [["192.0.2.0/24", "CA", "CA-ON", "Toronto", ""]]

    captured = capsys.readouterr()
    assert "198.51.100.0/24" in captured.err
    assert "scope id 999" in captured.err
    assert "192.0.2.0/25" not in captured.err
    assert "Exported 1 aggregated prefixes from 2 source prefixes" in captured.out
    assert "Skipped 1 prefixes with unresolved locations" in captured.out


def test_main_passes_tag_and_blocklist_from_environment(cli, monkeypatch):
    monkeypatch.setenv("NETBOX_TAG", " geofeed ")
    monkeypatch.setenv("NETBOX_PREFIX_BLOCKLIST", "192.0.2.0/25")

    with patch.object(
        netbox_prefix_exporter,
        "fetch_prefixes",
        return_value=[region_prefix("192.0.2.0/24", 3)],
    ) as fetch, patch.object(netbox_prefix_exporter, "fetch_regions", return_value=REGIONS):
        assert main() == 0

    fetch.assert_called_once_with("https://netbox.example.com", "secret", "geofeed")
    rows = list(csv.reader(cli.read_text(encoding="utf-8").splitlines()[2:]))
    assert rows == [["192.0.2.128/25", "CA", "CA-ON", "Toronto", ""]]


def test_main_reports_bad_blocklist_entry_before_contacting_netbox(cli, monkeypatch, capsys):
    monkeypatch.setenv("NETBOX_PREFIX_BLOCKLIST", "10.0.0.0/8,not-a-prefix")

    with patch.object(netbox_prefix_exporter, "fetch_prefixes") as fetch:
        with pytest.raises(SystemExit) as exit_info:
            main()

    assert exit_info.value.code == 2
    fetch.assert_not_called()
    error_text = capsys.readouterr().err
    assert "'not-a-prefix'" in error_text
    assert "NETBOX_PREFIX_BLOCKLIST" in error_text
    assert "Could not create geofeed" not in error_text


def test_main_reports_netbox_request_failures(cli, capsys):
    with patch.object(
        netbox_prefix_exporter,
        "fetch_prefixes",
        side_effect=requests.ConnectionError("boom"),
    ):
        with pytest.raises(SystemExit) as exit_info:
            main()

    assert exit_info.value.code == 2
    assert "NetBox request failed: boom" in capsys.readouterr().err


def test_main_requires_url_and_token(cli, monkeypatch, capsys):
    monkeypatch.delenv("NETBOX_TOKEN")

    with pytest.raises(SystemExit) as exit_info:
        main()

    assert exit_info.value.code == 2
    assert "NETBOX_URL and NETBOX_TOKEN" in capsys.readouterr().err
