import argparse
import csv
from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
import sys
from typing import Any

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


REGION_SCOPE_TYPE = "dcim.region"

# Short names for types that appear throughout the script.
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Record = dict[str, Any]  # one JSON object returned by NetBox
RegionIndex = dict[int, Record]  # every Region, keyed by its NetBox ID
Location = tuple[str, str, str]  # (country, region, city)
LocatedNetwork = tuple[IPNetwork, Location]

# Retry transient server errors so one hiccup does not abort a long paginated
# download. Only GET requests are retried (this script never writes to NetBox).
RETRY_POLICY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=(502, 503, 504),
    allowed_methods=("GET",),
)


def fetch_results(
    base_url: str,
    token: str,
    api_path: str,
    params: dict[str, str] | None = None,
) -> list[Record]:
    """Fetch every page of a NetBox list endpoint (read-only GET requests)."""
    endpoint = f"{base_url.rstrip('/')}/{api_path}"
    headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
    results: list[Record] = []

    with requests.Session() as session:
        adapter = HTTPAdapter(max_retries=RETRY_POLICY)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        next_url: str | None = endpoint
        page_params = params
        while next_url:
            response = session.get(next_url, headers=headers, params=page_params, timeout=30)
            response.raise_for_status()
            payload = response.json()
            results.extend(payload.get("results", []))
            next_url = payload.get("next")
            # NetBox's "next" URL already contains the query string, so the
            # filter parameters are only sent with the first request.
            page_params = None

    return results


def fetch_prefixes(
    base_url: str,
    token: str,
    tag: str | None = None,
) -> list[Record]:
    params = {"scope_type": REGION_SCOPE_TYPE}
    if tag:
        params["tag"] = tag

    return fetch_results(
        base_url,
        token,
        "api/ipam/prefixes/",
        params,
    )


def fetch_regions(base_url: str, token: str) -> RegionIndex:
    """Fetch every Region and return them keyed by NetBox ID for quick lookup."""
    regions = fetch_results(base_url, token, "api/dcim/regions/")
    return {region["id"]: region for region in regions}


def parse_blocklist(text: str) -> list[IPNetwork]:
    """Turn a comma-separated string of prefixes into a list of networks."""
    networks: list[IPNetwork] = []
    for entry in text.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as error:
            raise ValueError(
                f"Invalid entry {entry!r} in NETBOX_PREFIX_BLOCKLIST: {error}"
            ) from error
    return networks


def _parent_region(region: Record | None, regions_by_id: RegionIndex) -> Record | None:
    # NetBox returns "parent" as a nested object with an "id", or null.
    parent = region.get("parent") if region else None
    return regions_by_id.get(parent["id"]) if parent else None


def _geofeed_location(prefix: Record, regions_by_id: RegionIndex) -> Location:
    """Return (country, region, city) for a prefix, using "" for anything missing."""
    if prefix.get("scope_type") != REGION_SCOPE_TYPE or prefix.get("scope_id") is None:
        return "", "", ""

    city = regions_by_id.get(prefix["scope_id"])
    if city is None:
        return "", "", ""

    province = _parent_region(city, regions_by_id)
    country = _parent_region(province, regions_by_id)

    return (
        str(country.get("name", "")) if country else "",
        str(province.get("name", "")) if province else "",
        str(city.get("name", "")) if city else "",
    )


def split_by_location(
    prefixes: list[Record],
    regions_by_id: RegionIndex,
) -> tuple[list[LocatedNetwork], list[Record]]:
    """Separate prefixes into (located networks, unresolved prefixes).

    A prefix is unresolved when its country, region, or city cannot be
    determined, for example because a parent Region is missing in NetBox.
    Each located network is paired with its (country, region, city).
    """
    located: list[LocatedNetwork] = []
    unresolved: list[Record] = []
    for prefix in prefixes:
        location = _geofeed_location(prefix, regions_by_id)
        if all(location):
            network = ipaddress.ip_network(prefix["prefix"], strict=False)
            located.append((network, location))
        else:
            unresolved.append(prefix)
    return located, unresolved


def _subtract_blacklist(network: IPNetwork, blacklist: list[IPNetwork]) -> list[IPNetwork]:
    """Remove blocklisted address space from a network, returning the leftover CIDRs."""
    remaining = [network]
    for excluded in blacklist:
        next_remaining = []
        for candidate in remaining:
            if candidate.version != excluded.version or not candidate.overlaps(excluded):
                # Nothing to remove from this piece.
                next_remaining.append(candidate)
            elif candidate.subnet_of(excluded):
                # The whole piece is blocked, so drop it.
                continue
            else:
                # CIDR networks that overlap are always nested, so here the
                # blocked range sits inside the candidate: carve it out.
                next_remaining.extend(candidate.address_exclude(excluded))
        remaining = next_remaining
    return remaining


def write_aggregated_geofeed(
    located: list[LocatedNetwork],
    output_path: Path,
    generated_at: datetime | None = None,
    blacklist: list[IPNetwork] | None = None,
) -> int:
    generated_at = generated_at or datetime.now(timezone.utc)
    blacklist = blacklist or []

    # The IP version is part of the key because ipaddress.collapse_addresses()
    # raises TypeError if it is given a mix of IPv4 and IPv6 networks.
    networks_by_location: dict[tuple[str, str, str, int], list[IPNetwork]] = {}
    for network, location in located:
        key = (*location, network.version)
        networks_by_location.setdefault(key, []).extend(_subtract_blacklist(network, blacklist))

    rows = [
        (network, country, province, city)
        for (country, province, city, _), networks in networks_by_location.items()
        for network in ipaddress.collapse_addresses(networks)
    ]
    rows.sort(key=lambda row: (row[0].version, int(row[0].network_address)))

    # RFC 3339 timestamp in UTC, e.g. 2024-08-30T04:18:56+00:00
    timestamp = generated_at.astimezone(timezone.utc).isoformat(timespec="seconds")
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        csv_file.write(
            f"# RFC8805 geofeed generated {timestamp}\n"
            "# ip_prefix,alpha2code,region,city,postal_code\n"
        )
        writer = csv.writer(csv_file, lineterminator="\n")
        for network, country, province, city in rows:
            writer.writerow([str(network), country, province, city, ""])
    return len(rows)


def _describe_scope(prefix: Record, regions_by_id: RegionIndex) -> str:
    """Return e.g. "scope id 2 (CA-AB)", or just "scope id 2" if the Region is unknown."""
    scope_id = prefix.get("scope_id")
    region = regions_by_id.get(scope_id)
    if region and region.get("name"):
        return f"scope id {scope_id} ({region['name']})"
    return f"scope id {scope_id}"


def _report_unresolved(unresolved: list[Record], regions_by_id: RegionIndex) -> None:
    """Report every skipped prefix, followed by a count and advice.
    """
    if not unresolved:
        return

    for prefix in unresolved:
        scope = _describe_scope(prefix, regions_by_id)
        print(
            f"Warning: skipped {prefix.get('prefix')} with {scope}: "
            "its Region, or a parent Region, could not be resolved.",
            file=sys.stderr,
        )

    print(
        f"Skipped {len(unresolved)} prefixes with unresolved locations.",
        file=sys.stderr,
    )
    print(
        "Prefix Scope must be a city Region whose parent is a province/state and "
        'whose grandparent is a country -- see "Unresolved locations" in README.md',
        file=sys.stderr,
    )


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="Export Region-scoped NetBox IP prefixes as an RFC 8805 geofeed."
    )
    parser.add_argument("--base-url", default=os.getenv("NETBOX_URL"), help="NetBox base URL")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("geofeed.csv"),
        help="Aggregated geofeed output path",
    )
    args = parser.parse_args()

    token = os.getenv("NETBOX_TOKEN")
    if not args.base_url or not token:
        parser.error("Set NETBOX_URL and NETBOX_TOKEN in .env or the environment")

    # Parsed on its own so a typo in the blocklist gets a specific message.
    try:
        blacklist = parse_blocklist(os.getenv("NETBOX_PREFIX_BLOCKLIST", ""))
    except ValueError as error:
        parser.error(str(error))

    tag = os.getenv("NETBOX_TAG", "").strip() or None

    try:
        prefixes = fetch_prefixes(args.base_url, token, tag)
        regions_by_id = fetch_regions(args.base_url, token)
        located, unresolved = split_by_location(prefixes, regions_by_id)
        exported_count = write_aggregated_geofeed(located, args.output, blacklist=blacklist)
    except requests.RequestException as error:
        parser.error(f"NetBox request failed: {error}")
    except (KeyError, ValueError) as error:
        parser.error(f"Could not create geofeed: {error}")
    else:
        _report_unresolved(unresolved, regions_by_id)
        print(
            f"Exported {exported_count} aggregated prefixes "
            f"from {len(located)} source prefixes to {args.output}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
