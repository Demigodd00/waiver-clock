# Synthetic mitigation evidence — bounded documentation exception

This is a public demonstration fixture, not a security certification.

Subject: `docs/release-notes-2.0.md` only. The exception permits one markdown
table showing the three API mappings in the necessity evidence. It does not
permit tables elsewhere or any change to application source.

Compensating measures:

1. Documentation owner: the maintainer wallet recorded in the WaiverClock request.
2. An accessible prose alternative is included immediately after the table:
   `/v1/items` becomes `/v2/items` and `item_id` becomes `id`;
   `/v1/search` becomes `/v2/query` and `q` moves into the JSON body;
   `/v1/report` becomes `/v2/reports` and CSV selection uses `Accept: text/csv`.
3. The exception lasts at most 60 minutes. The contract automatically reports
   it inactive at expiry, even if no keeper calls the explicit expiry method.
4. The owner may revoke it earlier. Any change to control `DOC-001` invalidates
   the approval immediately.
