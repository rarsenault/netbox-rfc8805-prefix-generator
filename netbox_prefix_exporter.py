import argparse
import csv
from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
from typing import Any
from urllib.parse import urljoin
from zoneinfo import ZoneInfo

import requests
from dotenv import load_dotenv


REGION_SCOPE_TYPE = "dcim.region"
EASTERN_TIME = ZoneInfo("America/New_York")
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _write_geofeed_header(csv_file: Any, purpose: str, generated_at: datetime) -> csv.writer:
    local = generated_at.astimezone(EASTERN_TIME)
    zone = "Eastern Daylight Time" if local.dst() else "Eastern Standard Time"
    csv_file.write(
        f"# {purpose} generated {local:%B} {local.day} {local:%Y - %H:%M:%S} ({zone})\n"
        "# ip_prefix,alpha2code,region,city,postal_code\n"
    )
    return csv.writer(csv_file, lineterminator="\n")


def fetch_results(
    base_url: str,
    token: str,
    api_path: str,
    params: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    endpoint = urljoin(base_url.rstrip("/") + "/", api_path)
    headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
    results: list[dict[str, Any]] = []

    with requests.Session() as session:
        next_url: str | None = endpoint
        while next_url:
            response = session.get(next_url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            payload = response.json()
            results.extend(payload.get("results", []))
            next_url = payload.get("next")
            if next_url:
                next_url = urljoin(endpoint, next_url)
            params = None

    return results


def fetch_prefixes(base_url: str, token: str) -> list[dict[str, Any]]:
    return fetch_results(
        base_url,
        token,
        "api/ipam/prefixes/",
        {"scope_type": REGION_SCOPE_TYPE},
    )


def fetch_regions(base_url: str, token: str) -> list[dict[str, Any]]:
    return fetch_results(base_url, token, "api/dcim/regions/")


def _region_index(regions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(region["id"]): region for region in regions if region.get("id") is not None}


def _parent_region(
    region: dict[str, Any] | None,
    regions_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    parent = region.get("parent") if region else None
    parent_id = parent.get("id") if isinstance(parent, dict) else parent
    return regions_by_id.get(str(parent_id)) if parent_id is not None else None


def _geofeed_location(
    prefix: dict[str, Any],
    regions_by_id: dict[str, dict[str, Any]],
) -> tuple[str, str, str]:
    if prefix.get("scope_type") != REGION_SCOPE_TYPE or prefix.get("scope_id") is None:
        return "", "", ""

    city = regions_by_id.get(str(prefix["scope_id"]))
    if city is None:
        return "", "", ""

    province = _parent_region(city, regions_by_id)
    country = _parent_region(province, regions_by_id)

    return (
        str(country.get("name", "")) if country else "",
        str(province.get("name", "")) if province else "",
        str(city.get("name", "")) if city else "",
    )


def _subtract_blacklist(network: IPNetwork, blacklist: list[IPNetwork]) -> list[IPNetwork]:
    remaining = [network]
    for excluded in blacklist:
        next_remaining = []
        for candidate in remaining:
            if candidate.version != excluded.version or not candidate.overlaps(excluded):
                next_remaining.append(candidate)
            elif candidate.subnet_of(excluded):
                continue
            elif excluded.subnet_of(candidate):
                next_remaining.extend(candidate.address_exclude(excluded))
        remaining = next_remaining
    return remaining


def write_aggregated_geofeed(
    prefixes: list[dict[str, Any]],
    regions: list[dict[str, Any]],
    output_path: Path,
    generated_at: datetime | None = None,
    blacklist: list[IPNetwork] | None = None,
) -> int:
    regions_by_id = _region_index(regions)
    generated_at = generated_at or datetime.now(timezone.utc)
    blacklist = blacklist or []
    networks_by_location: dict[tuple[str, str, str, int], list[Any]] = {}
    for prefix in prefixes:
        location = _geofeed_location(prefix, regions_by_id)
        network = ipaddress.ip_network(prefix["prefix"], strict=False)
        key = (*location, network.version)
        networks_by_location.setdefault(key, []).extend(_subtract_blacklist(network, blacklist))

    rows = [
        (network, country, province, city)
        for (country, province, city, _), networks in networks_by_location.items()
        for network in ipaddress.collapse_addresses(networks)
    ]
    rows.sort(key=lambda row: (row[0].version, int(row[0].network_address)))
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = _write_geofeed_header(
            csv_file,
            "Aggregated RFC8805 geofeed",
            generated_at,
        )
        for network, country, province, city in rows:
            writer.writerow([str(network), country, province, city, ""])
    return len(rows)


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="Export Region-scoped NetBox IP prefixes as an RFC 8805 geofeed."
    )
    parser.add_argument("--base-url", default=os.getenv("NETBOX_URL"), help="NetBox base URL")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("geofeed-aggregated.csv"),
        help="Aggregated geofeed output path",
    )
    args = parser.parse_args()

    token = os.getenv("NETBOX_TOKEN")
    if not args.base_url or not token:
        parser.error("Set NETBOX_URL and NETBOX_TOKEN in .env or the environment")

    try:
        blacklist = [
            ipaddress.ip_network(value.strip(), strict=False)
            for value in os.getenv("NETBOX_PREFIX_BLOCKLIST", "").split(",")
            if value.strip()
        ]
        prefixes = fetch_prefixes(args.base_url, token)
        regions = fetch_regions(args.base_url, token)
        generated_at = datetime.now(timezone.utc)
        exported_count = write_aggregated_geofeed(
            prefixes,
            regions,
            args.output,
            generated_at,
            blacklist,
        )
    except requests.RequestException as error:
        parser.error(f"NetBox request failed: {error}")
    except (KeyError, ValueError) as error:
        parser.error(f"Could not create geofeed: {error}")

    print(
        f"Exported {exported_count} aggregated prefixes "
        f"from {len(prefixes)} source prefixes to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
