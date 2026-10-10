import csv
from datetime import datetime, timezone
import ipaddress
from unittest.mock import Mock, patch

from netbox_prefix_exporter import (
    fetch_prefixes,
    fetch_regions,
    write_aggregated_geofeed,
)


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


def test_write_aggregated_geofeed_collapses_only_matching_locations(tmp_path):
    output = tmp_path / "geofeed-aggregated.csv"
    generated_at = datetime(2024, 8, 30, 4, 18, 56, tzinfo=timezone.utc)
    regions = [
        {"id": 1, "name": "CA", "parent": None},
        {"id": 2, "name": "CA-ON", "parent": {"id": 1}},
        {"id": 3, "name": "Toronto", "parent": {"id": 2}},
        {"id": 4, "name": "Ottawa", "parent": {"id": 2}},
    ]
    exported_count = write_aggregated_geofeed(
        [
            {"prefix": "192.0.2.0/25", "scope_type": "dcim.region", "scope_id": 3},
            {"prefix": "192.0.2.128/25", "scope_type": "dcim.region", "scope_id": 3},
            {"prefix": "198.51.100.0/24", "scope_type": "dcim.region", "scope_id": 4},
            {"prefix": "2001:db8::/33", "scope_type": "dcim.region", "scope_id": 3},
            {"prefix": "2001:db8:8000::/33", "scope_type": "dcim.region", "scope_id": 3},
        ],
        regions,
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


def test_write_aggregated_geofeed_subtracts_blacklisted_address_ranges(tmp_path):
    output = tmp_path / "geofeed-aggregated.csv"
    regions = [
        {"id": 1, "name": "CA", "parent": None},
        {"id": 2, "name": "CA-ON", "parent": {"id": 1}},
        {"id": 3, "name": "Toronto", "parent": {"id": 2}},
    ]

    exported_count = write_aggregated_geofeed(
        [
            {"prefix": "192.0.2.0/24", "scope_type": "dcim.region", "scope_id": 3},
            {"prefix": "198.51.100.0/24", "scope_type": "dcim.region", "scope_id": 3},
            {"prefix": "2001:db8::/32", "scope_type": "dcim.region", "scope_id": 3},
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
