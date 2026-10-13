import argparse
import csv
from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urljoin
from zoneinfo import ZoneInfo

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


REGION_SCOPE_TYPE = "dcim.region"
EASTERN_TIME = ZoneInfo("America/New_York")
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Month names are spelled out here instead of using "%B" because "%B" changes
# with the system locale, and the geofeed header should always be in English.
MONTH_NAMES = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)
# Keyed by whether daylight saving time is in effect.
ZONE_NAMES = {True: "Eastern Daylight Time", False: "Eastern Standard Time"}

# Retry transient server errors so one hiccup does not abort a long paginated
# download. Only GET requests are retried (this script never writes to NetBox).
RETRY_POLICY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=(502, 503, 504),
    allowed_methods=("GET",),
)


def _write_geofeed_header(csv_file: Any, purpose: str, generated_at: datetime) -> csv.writer:
    local = generated_at.astimezone(EASTERN_TIME)
    zone = ZONE_NAMES[bool(local.dst())]
    month = MONTH_NAMES[local.month - 1]
    csv_file.write(
        f"# {purpose} generated {month} {local.day} {local:%Y - %H:%M:%S} ({zone})\n"
        "# ip_prefix,alpha2code,region,city,postal_code\n"
    )
    return csv.writer(csv_file, lineterminator="\n")


def fetch_results(
    base_url: str,
    token: str,
    api_path: str,
    params: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Fetch every page of a NetBox list endpoint (read-only GET requests)."""
    endpoint = urljoin(base_url.rstrip("/") + "/", api_path)
    headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
    results: list[dict[str, Any]] = []

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
) -> list[dict[str, Any]]:
    params = {"scope_type": REGION_SCOPE_TYPE}
    if tag:
        params["tag"] = tag

    return fetch_results(
        base_url,
        token,
        "api/ipam/prefixes/",
        params,
    )


def fetch_regions(base_url: str, token: str) -> list[dict[str, Any]]:
    return fetch_results(base_url, token, "api/dcim/regions/")


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


def _region_index(regions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(region["id"]): region for region in regions if region.get("id") is not None}


def _parent_region(
    region: dict[str, Any] | None,
    regions_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    # NetBox returns "parent" as a nested object with an "id", or null.
    parent = region.get("parent") if region else None
    return regions_by_id.get(str(parent["id"])) if parent else None


def _geofeed_location(
    prefix: dict[str, Any],
    regions_by_id: dict[str, dict[str, Any]],
) -> tuple[str, str, str]:
    """Return (country, region, city) for a prefix, using "" for anything missing."""
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


def split_by_location(
    prefixes: list[dict[str, Any]],
    regions: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Separate prefixes into (fully located, unresolved).

    A prefix is unresolved when its country, region, or city cannot be
    determined, for example because a parent Region is missing in NetBox.
    """
    regions_by_id = _region_index(regions)
    located: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    for prefix in prefixes:
        if all(_geofeed_location(prefix, regions_by_id)):
            located.append(prefix)
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
    prefixes: list[dict[str, Any]],
    regions: list[dict[str, Any]],
    output_path: Path,
    generated_at: datetime | None = None,
    blacklist: list[IPNetwork] | None = None,
) -> int:
    regions_by_id = _region_index(regions)
    generated_at = generated_at or datetime.now(timezone.utc)
    blacklist = blacklist or []

    # The IP version is part of the key because ipaddress.collapse_addresses()
    # raises TypeError if it is given a mix of IPv4 and IPv6 networks.
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


def _report_unresolved(unresolved: list[dict[str, Any]]) -> None:
    """Print one warning per skipped prefix so problems can be fixed in NetBox."""
    for prefix in unresolved:
        print(
            f"Warning: skipped {prefix.get('prefix')} (scope id {prefix.get('scope_id')}): "
            "its Region, or a parent Region, could not be resolved",
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
        default=Path("geofeed-aggregated.csv"),
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
        regions = fetch_regions(args.base_url, token)
        located, unresolved = split_by_location(prefixes, regions)
        exported_count = write_aggregated_geofeed(
            located,
            regions,
            args.output,
            datetime.now(timezone.utc),
            blacklist,
        )
    except requests.RequestException as error:
        parser.error(f"NetBox request failed: {error}")
    except (KeyError, ValueError) as error:
        parser.error(f"Could not create geofeed: {error}")
    else:
        _report_unresolved(unresolved)
        print(
            f"Exported {exported_count} aggregated prefixes "
            f"from {len(located)} source prefixes to {args.output}"
        )
        if unresolved:
            print(
                f"Skipped {len(unresolved)} prefixes with unresolved locations "
                "(see warnings above)"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
