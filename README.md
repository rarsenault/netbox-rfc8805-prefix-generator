# Netbox RFC8805 Prefix Generator

Export Netbox IPAM prefixes to an [RFC8805](https://www.rfc-editor.org/rfc/rfc8805.txt)-compliant geofeed CSV file.

## Requirements

- Python 3.10 or later
- NetBox 4.2 or later
- A NetBox API token with permission to view IPAM prefixes and DCIM Regions
- Python packages listed in `requirements.txt`
- Use the [ISO Online Browsing Platform](https://www.iso.org/obp/ui/) as the
  source for country and subdivision codes.

Create NetBox Regions in a three-level hierarchy with these layers:

- **Country:** the top layer, represented by the two-letter ISO 3166-1
  alpha-2 code (for example, `CA` for Canada).
  - This becomes the RFC 8805 `alpha2code` field.
- **Province/state:** the second layer, represented by an ISO 3166-2
  subdivision code (for example, `CA-PE` for Prince Edward Island).
  - This becomes the RFC 8805 `region` field.
- **City:** the third layer, represented by a real city name.
  - This becomes the RFC 8805 `city` field.

The following is an example, using Canada as a reference country:

```text
Regions
└── CA
    ├── CA-ON
    │   ├── Ottawa
    │   └── Toronto
    └── CA-PE
        ├── Charlottetown
        └── Elmsdale
```

Within Netbox, set each relevant Prefix's **Scope** to its city Region. The exporter follows
that city's parent hierarchy to populate the corresponding geofeed fields.

Ex: Assume `192.0.2.0/29` is assigned to Charlottetown. Its Scope should be set to the `Charlottetown` Region. The script will derive the relevant provice/state and country codes. If the Scope Region cannot be
resolved or a parent Region is missing, the corresponding location fields will
be blank.

## Setup

Create and activate a virtual environment, then install the required packages:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Define the NetBox URL and API token in `.env`:

```dotenv
NETBOX_URL=https://netbox.example.com
NETBOX_TOKEN=your-token-value
NETBOX_TAG=
NETBOX_PREFIX_BLOCKLIST=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,2001:db8::/32
```

`NETBOX_TAG` is optional. Leave it empty to consider all Region-scoped
prefixes, or set it to one NetBox tag slug to include only Region-scoped prefixes with that
tag.

`NETBOX_PREFIX_BLOCKLIST` is optional. Enter comma-separated IP prefixes to
exclude; the example lists RFC 1918 private IPv4 ranges and the IPv6
documentation range from RFC 3849. If a blocklist overlaps only part of a
NetBox prefix, the exporter removes that address range and exports the
remaining CIDR pieces with the original location. Leave the value empty to
disable exclusions.

The exporter fetches only prefixes whose Scope type is Region (`dcim.region`),
and, if `NETBOX_TAG` is set, only those with the configured tag. The blacklist
is then applied to the selected prefixes. Prefixes without a Region Scope or
without the configured tag are excluded. If a blacklisted prefix is contained
within a less-specific NetBox prefix, the exporter splits the less-specific
prefix into CIDR ranges that exclude the blocked addresses. Those remaining
ranges retain the location of the less-specific prefix.

## Run

Call ```python3 ./netbox_prefix_exporter.py```.

By default, this writes `geofeed-aggregated.csv` in the current directory.
Use `--output` to choose a different path, ex:

```./netbox_prefix_exporter.py --output ./foo/bar/geofeed-aggregated.csv```

The CSV begins with a generated-time comment and a field-definition comment,
followed by aggregated rows. Example output (timestamp shown for illustration):

```text
# Aggregated RFC8805 geofeed generated October 1 2026 - 00:18:56 (Eastern Daylight Time)
# ip_prefix,alpha2code,region,city,postal_code
192.0.2.0/24,CA,CA-ON,Toronto,
```

Adjacent IPv4 or IPv6 networks are aggregated only when their country, region,
and city fields are identical. Networks with different locations are not
merged.

## Notes & Suggestions

Prefixes without a Region Scope are excluded by the NetBox API filter and will not appear in the CSV.

Before publishing the feed for ingestion by external parties, the generated CSV should be validated. An example validator is [geofeed-validator](https://github.com/massimocandela/geofeed-validator/releases/).
Download the release binary for your operating system and run it against the
output file. For example, on Linux:

```sh
./geofeed-validator-linux-x64 -f geofeed-aggregated.csv
```

Validation can catch formatting and location-code errors, but it does not
confirm that locations are accurate. Before publishing, review the
`alpha2code`, `region`, and `city` columns in `geofeed-aggregated.csv` for blank
values or locations that do not match the expected prefix location. Blank
values usually mean the Scope Region or one of its parent Regions is missing
or cannot be resolved. Correct the Region hierarchy or Prefix Scope in NetBox,
run the exporter again, and review the updated CSV.