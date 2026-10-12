# Synthetic necessity evidence — documentation formatting exception

This is a public demonstration fixture, not a real production incident.

Subject: `docs/release-notes-2.0.md`.
Control: `DOC-001`, which requires prose-only release notes.
Requested deviation: allow one small markdown table for the three-column
mapping from previous API version, replacement API version, and migration
action in this one document. No other document is in scope.

The demonstration release note contains these three dependent mappings:

| Previous | Replacement | Required migration action |
| --- | --- | --- |
| `/v1/items` | `/v2/items` | Rename `item_id` to `id` |
| `/v1/search` | `/v2/query` | Move `q` into JSON body |
| `/v1/report` | `/v2/reports` | Replace `format=csv` with `Accept: text/csv` |

The pilot's table-rendering test requires the mapping to be represented as a
three-column markdown table. A prose-only version cannot exercise that test.
The exception is limited to the synthetic test document and does not relax
any production dependency, security, or data-handling requirement.
