from pathlib import Path
import hashlib
import json
import sys


CONTRACT = Path(__file__).resolve().parents[2] / "contracts" / "WaiverClock.py"
SDK = "v0.2.16"
ROOT = "https://raw.githubusercontent.com/example/waiver-clock/" + "a" * 40 + "/evidence/"
NEED = "The required parser is unavailable under the current approved dependency list."
MITIGATION = "Pin a local fork, disable network access, assign an owner, and remove within one day."
RULE = "Do not use unapproved network-capable dependencies in the report pipeline."


def addr(value):
    return "0x" + value.hex()


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def unpack(contract, request_id):
    return json.loads(contract.get_request(request_id))


def warp(vm, timestamp):
    """Keep the direct VM and the SDK's cached message timestamp in sync."""
    vm.warp(timestamp)
    gl = sys.modules.get("genlayer.gl")
    if gl is not None and getattr(gl, "message_raw", None) is not None:
        gl.message_raw["datetime"] = timestamp


def setup(vm, direct_deploy, owner, maintainer):
    warp(vm, "2026-10-12T00:00:00Z")
    vm.sender = owner
    contract = direct_deploy(str(CONTRACT), sdk_version=SDK)
    contract.create_control("DEP-001", RULE, 86400)
    contract.set_maintainer(addr(maintainer), True)
    return contract


def request(vm, contract, maintainer, *, need=NEED, mitigation=MITIGATION, suffix="v1", subject="parserlib@2.4"):
    need_url = ROOT + "necessity-" + suffix + ".txt"
    mitigation_url = ROOT + "mitigation-" + suffix + ".txt"
    vm.mock_web(need_url, {"status": 200, "body": need})
    vm.mock_web(mitigation_url, {"status": 200, "body": mitigation})
    vm.sender = maintainer
    return contract.request_waiver(
        "DEP-001", subject, "Use a local fork only for report generation.", 3600,
        need_url, digest(need), mitigation_url, digest(mitigation),
    )


def judge(vm, *, need="NO_COMPLIANT_PATH", mitigation="BOUNDED_MITIGATION"):
    vm.mock_llm("Assess only whether a temporary exception", json.dumps({"finding_code": need}))
    vm.mock_llm("Assess only whether the proposed compensating", json.dumps({"finding_code": mitigation}))


def assess(contract, request_id):
    contract.assess_necessity(request_id)
    contract.assess_mitigation(request_id)
    contract.finalize_request(request_id)


def test_pass_activates_then_expires(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = setup(direct_vm, direct_deploy, direct_alice, direct_bob)
    request_id = request(direct_vm, contract, direct_bob)
    judge(direct_vm)
    assess(contract, request_id)
    result = unpack(contract, request_id)
    assert result["status"] == "ACTIVE"
    assert result["necessity"]["finding_code"] == "NO_COMPLIANT_PATH"
    assert result["mitigation"]["finding_code"] == "BOUNDED_MITIGATION"
    assert contract.is_waiver_active(addr(direct_bob), "DEP-001", "parserlib@2.4") is True
    warp(direct_vm, "2026-10-12T01:00:00Z")
    assert contract.is_waiver_active(addr(direct_bob), "DEP-001", "parserlib@2.4") is False
    assert unpack(contract, request_id)["effective_status"] == "EXPIRED"
    contract.expire_waiver(request_id)
    assert unpack(contract, request_id)["status"] == "EXPIRED"


def test_independent_validator_replays_both_dimensions(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = setup(direct_vm, direct_deploy, direct_alice, direct_bob)
    request_id = request(direct_vm, contract, direct_bob)
    judge(direct_vm)
    contract.assess_necessity(request_id)
    leader = direct_vm._captured_validators[-1][0]
    assert direct_vm.run_validator(leader_result=leader) is True
    contract.assess_mitigation(request_id)
    leader = direct_vm._captured_validators[-1][0]
    assert direct_vm.run_validator(leader_result=leader) is True


def test_concrete_failure_denies_even_if_other_dimension_passes(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = setup(direct_vm, direct_deploy, direct_alice, direct_bob)
    request_id = request(direct_vm, contract, direct_bob)
    judge(direct_vm, need="NOT_NECESSARY")
    assess(contract, request_id)
    assert unpack(contract, request_id)["status"] == "DENIED"
    assert contract.is_waiver_active(addr(direct_bob), "DEP-001", "parserlib@2.4") is False


def test_concern_requires_review_not_activation(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = setup(direct_vm, direct_deploy, direct_alice, direct_bob)
    request_id = request(direct_vm, contract, direct_bob)
    judge(direct_vm, mitigation="INCOMPLETE_MITIGATION")
    assess(contract, request_id)
    assert unpack(contract, request_id)["status"] == "REVIEW_REQUIRED"


def test_tampered_mitigation_fails_closed(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = setup(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.mock_web(ROOT + "necessity-v1.txt", {"status": 200, "body": NEED})
    direct_vm.mock_web(ROOT + "mitigation-v1.txt", {"status": 200, "body": "tampered"})
    direct_vm.sender = direct_bob
    request_id = contract.request_waiver(
        "DEP-001", "parserlib@2.4", "Use a local fork only for report generation.", 3600,
        ROOT + "necessity-v1.txt", digest(NEED),
        ROOT + "mitigation-v1.txt", digest(MITIGATION),
    )
    judge(direct_vm)
    assess(contract, request_id)
    result = unpack(contract, request_id)
    assert result["mitigation"]["evidence_state"] == "HASH_MISMATCH"
    assert result["status"] == "REVIEW_REQUIRED"


def test_unauthorized_request_and_owner_control(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie):
    contract = setup(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.sender = direct_charlie
    with direct_vm.expect_revert("maintainer_required"):
        contract.request_waiver("DEP-001", "parserlib@2.4", "Deviation", 3600, ROOT + "n.txt", "a" * 64, ROOT + "m.txt", "b" * 64)
    with direct_vm.expect_revert("owner_required"):
        contract.revise_control("DEP-001", "Different rule", 3600)
    with direct_vm.expect_revert("owner_required"):
        contract.set_maintainer(addr(direct_charlie), True)


def test_policy_revision_invalidates_without_iteration(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = setup(direct_vm, direct_deploy, direct_alice, direct_bob)
    request_id = request(direct_vm, contract, direct_bob)
    judge(direct_vm)
    assess(contract, request_id)
    direct_vm.sender = direct_alice
    contract.revise_control("DEP-001", "Only vetted local dependencies are allowed.", 86400)
    assert unpack(contract, request_id)["effective_status"] == "SUPERSEDED"
    assert contract.is_waiver_active(addr(direct_bob), "DEP-001", "parserlib@2.4") is False


def test_role_revocation_invalidates_active_waiver(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = setup(direct_vm, direct_deploy, direct_alice, direct_bob)
    request_id = request(direct_vm, contract, direct_bob)
    judge(direct_vm)
    assess(contract, request_id)
    direct_vm.sender = direct_alice
    contract.set_maintainer(addr(direct_bob), False)
    assert unpack(contract, request_id)["effective_status"] == "ROLE_REVOKED"
    assert contract.is_waiver_active(addr(direct_bob), "DEP-001", "parserlib@2.4") is False
    contract.set_maintainer(addr(direct_bob), True)
    assert unpack(contract, request_id)["effective_status"] == "ROLE_REVOKED"
    assert contract.is_waiver_active(addr(direct_bob), "DEP-001", "parserlib@2.4") is False


def test_owner_revocation_and_duplicate_prevention(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = setup(direct_vm, direct_deploy, direct_alice, direct_bob)
    request_id = request(direct_vm, contract, direct_bob)
    judge(direct_vm)
    assess(contract, request_id)
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("waiver_already_active"):
        contract.request_waiver("DEP-001", "parserlib@2.4", "Deviation", 3600, ROOT + "n2.txt", "c" * 64, ROOT + "m2.txt", "d" * 64)
    with direct_vm.expect_revert("owner_required"):
        contract.revoke_waiver(request_id, "Stop")
    direct_vm.sender = direct_alice
    contract.revoke_waiver(request_id, "Mitigation is no longer maintained")
    assert unpack(contract, request_id)["status"] == "REVOKED"


def test_renewal_requires_two_fresh_hashes(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = setup(direct_vm, direct_deploy, direct_alice, direct_bob)
    request_id = request(direct_vm, contract, direct_bob)
    judge(direct_vm)
    assess(contract, request_id)
    warp(direct_vm, "2026-10-12T01:00:00Z")
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("fresh_evidence_required"):
        request(direct_vm, contract, direct_bob, suffix="v2")
    new_id = request(direct_vm, contract, direct_bob, need=NEED + " Updated.", mitigation=MITIGATION + " Rechecked.", suffix="v3")
    assert unpack(contract, new_id)["previous_id"] == int(request_id)
    assert unpack(contract, request_id)["status"] == "EXPIRED"


def test_unfinished_assessment_times_out(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = setup(direct_vm, direct_deploy, direct_alice, direct_bob)
    request_id = request(direct_vm, contract, direct_bob)
    with direct_vm.expect_revert("assessments_required"):
        contract.finalize_request(request_id)
    warp(direct_vm, "2026-10-20T00:00:00Z")
    contract.finalize_request(request_id)
    assert unpack(contract, request_id)["status"] == "TIMED_OUT"


def test_changed_policy_closes_pending_request(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = setup(direct_vm, direct_deploy, direct_alice, direct_bob)
    request_id = request(direct_vm, contract, direct_bob)
    direct_vm.sender = direct_alice
    contract.revise_control("DEP-001", "A new frozen rule.", 86400)
    contract.finalize_request(request_id)
    assert unpack(contract, request_id)["status"] == "SUPERSEDED"


def test_no_native_value_accepted(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = setup(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.value = 1
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("value_not_accepted"):
        contract.create_control("NEW-001", "Rule", 3600)
    direct_vm.value = 0
