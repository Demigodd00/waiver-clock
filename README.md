# WaiverClock

WaiverClock is a standalone GenLayer Intelligent Contract for narrowly scoped, expiring exceptions to versioned project controls. It contains **no frontend, dashboard, or end-user app**. The contract owns the policy-exception state and validator judgments; it does not modify external software or override an external organization's rules.

An owner creates a control and names maintainers. A maintainer requests an exception for one exact subject and deviation, duration, and two distinct full-commit GitHub evidence files with SHA-256 digests. Validators independently fetch and hash the files, then assess **necessity** and **mitigation** in separate transactions. The two findings are stored separately. Only two `PASS` outcomes activate an exception. A concrete failure denies it; concern or missing evidence requires a new, better-supported request. Anyone may drive assessments and finalization within a seven-day window.

An activated exception stops being effective when its time expires, its control is revised, its maintainer authorization changes, or the owner revokes it. No batch sweep is needed for the read path. A renewal must use new necessity **and** mitigation evidence hashes, and the old approval remains in history.

See [the protocol](docs/PROTOCOL.md) for exact state transitions and limitations.

## Repository contents

- [`contracts/WaiverClock.py`](contracts/WaiverClock.py) — single-file Intelligent Contract with a pinned GenVM runner
- [`tests/direct/test_waiver_clock.py`](tests/direct/test_waiver_clock.py) — direct state-machine, authorization, timeout, evidence, and validator-replay tests
- [`evidence/demo/`](evidence/demo/) — public synthetic evidence for a non-security-critical demo control
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — decision and threat model

## Verification

```sh
python -m pip install -r requirements.txt
genvm-lint check contracts/WaiverClock.py --json
pytest tests/direct -q
```

The exception is an **on-chain WaiverClock status**, which other systems can choose to consult. It does not make an external dependency safe, perform security certification, or guarantee legal or organizational compliance. Evidence must be public and non-sensitive; private records are not suitable for the current protocol.
