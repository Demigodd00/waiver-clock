# WaiverClock protocol

## Policy and roles

The contract owner creates a named control (`control_id`, on-chain rule text, maximum exception duration). Each revision increments that control's version, which instantly makes earlier approvals ineffective without scanning them. The owner grants or revokes maintainer roles. A role epoch is recorded on every request: revoking and later re-enabling a maintainer cannot reactivate an old waiver.

## Request and evidence

A maintainer specifies one exact subject, the temporary deviation, a duration between 60 seconds and the control maximum (at most 30 days), and distinct necessity/mitigation evidence references. Each reference must be a public raw GitHub URL pinned to a 40-character commit ID and an exact SHA-256 digest. Validators fetch at most 6,000 bytes per file. A missing, overlarge, non-UTF-8, or hash-mismatched file cannot produce a `PASS` finding. Material inside evidence files is data, not instructions to the validators.

There is one open request or active waiver per maintainer/control/subject slot. This prevents concurrent approvals for the same exception. A new request links to the previous one in that slot. After an approval, both evidence hashes must change before another request can be made.

## Independent findings

`assess_necessity` and `assess_mitigation` are separate public transactions. Each transaction makes validators refetch its own pinned evidence and independently produce a substantive finding code. The leader and validators must agree on the dimension, evidence state, finding code, and derived outcome—not merely a valid JSON shape.

| Dimension | PASS | CONCERN | FAIL |
| --- | --- | --- | --- |
| Necessity | `NO_COMPLIANT_PATH` | `POSSIBLE_ALTERNATIVE` | `NOT_NECESSARY` |
| Mitigation | `BOUNDED_MITIGATION` | `INCOMPLETE_MITIGATION` | `UNMITIGATED_RISK` |

If evidence is missing or malformed, or the LLM returns no recognized finding code, the dimension stores `INSUFFICIENT_EVIDENCE`. No approval follows. These are subjective judgments based on supplied public material; they do not independently prove a maintainer's real-world claims.

## Finalization and lifecycle

Anyone can finalize a fully assessed request. Two passes activate a waiver from the finalization time until `activated_at + duration`. Any fail denies it. Otherwise the request ends as `REVIEW_REQUIRED`; the owner cannot silently override this result, but a maintainer may submit a new request with better evidence. Unfinished requests expire seven days after creation. A control revision or role revocation closes a pending request without approval.

An owner may revoke an active waiver with a stored reason. Anyone may materialize its expiry after the deadline. Even before that transaction, `is_waiver_active` and `get_request.effective_status` evaluate time, control version, and role epoch, so an expired or superseded waiver cannot be reported active. A revision never retroactively changes the historical finding codes.

## Boundaries

WaiverClock does not execute software, deploy packages, audit binary behavior, compel external projects to honor its status, or certify safety. In particular, it cannot guarantee that evidence remains hosted after approval. Consumers must explicitly decide whether and how to use the on-chain active-status view. Avoid using the sample documentation-policy evidence as a claim about a real dependency or security control.
