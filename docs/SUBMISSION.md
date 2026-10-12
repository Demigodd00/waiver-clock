# Intelligent Contracts submission

**Contribution date:** 12/10/2026

**Category:** Intelligent Contracts

**Title:** WaiverClock — Evidence-Bound Expiring Policy Exceptions

**Notes / Description:**

WaiverClock is a standalone GenLayer Intelligent Contract for scoped, expiring exceptions to versioned project rules—not a user-facing app. An authorized maintainer requests one exact deviation and duration with distinct, full-commit GitHub necessity and mitigation evidence. Validators independently fetch and SHA-256-check each file, then make two separately stored substantive findings. Only two passes activate the exception; a failure denies it, while concern or missing evidence requires a new request. Deterministic control versions, role epochs, expiry, revocation, and fresh-evidence renewal prevent stale approvals from remaining active. A synthetic StudioNet demo finalized both verified findings as PASS and activated a one-hour documentation exception. The deployed source matches the public commit; 13 direct tests pass. WaiverClock does not change external software or certify security.

**Evidence links:** add each separately.

1. Public repository: https://github.com/Demigodd00/waiver-clock
2. Exact deployed contract source: https://github.com/Demigodd00/waiver-clock/blob/f9453a2cc7500ac87923e4cdbc9c69e2adf43353/contracts/WaiverClock.py
3. StudioNet contract: https://explorer-studio.genlayer.com/address/0xeF9aFB82e72256b3A5d41c548D3faF5E4AECb0e8
4. Deployment and transaction record: https://github.com/Demigodd00/waiver-clock/blob/main/deployments/studionet.json
5. Synthetic evidence: https://github.com/Demigodd00/waiver-clock/tree/f9453a2cc7500ac87923e4cdbc9c69e2adf43353/evidence/demo
6. Protocol and limitations: https://github.com/Demigodd00/waiver-clock/blob/main/docs/PROTOCOL.md
7. Direct tests: https://github.com/Demigodd00/waiver-clock/blob/main/tests/direct/test_waiver_clock.py

The demo owner key was intentionally not retained, and the one-hour waiver may now be expired. Describe the observed activation as a completed demonstration, not as a currently operational exception. Submission does not guarantee steward acceptance.
