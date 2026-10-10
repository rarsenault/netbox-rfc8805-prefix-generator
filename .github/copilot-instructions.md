# Project Guidance

- Keep NetBox credentials in `.env`; never commit tokens or real environment files.
- Keep the exporter beginner-friendly and use the existing `requests` and `python-dotenv` dependencies.
- Add or update focused tests when changing API pagination, filtering, or CSV output.
- Do not make live NetBox calls in tests; mock HTTP responses instead.
- NEVER write anything to Netbox itself; the exporter MUST be read-only.
