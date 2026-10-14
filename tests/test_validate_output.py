import copy
from pathlib import Path

from tests.test_normalise_text import ALERT
from triage.playbooks import load
from triage.validate_output import check

PLAYBOOK = load(Path("playbooks/T1685.005.yml"))
GOOD = {
    "alert_id": "A-0001",
    "explanation": "The Security log on WIN-LAB01 was cleared by LAB\\labadmin.",
    "severity": "high",
    "assessment": "uncertain",
    "cited_fields": ["Computer", "SubjectUserName", "EventID"],
    "steps": [
        {"action": "Ask IT whether the clear was planned.", "playbook_step_id": "T1685.005-1"},
        {"action": "Disable the account.", "playbook_step_id": "T1685.005-3"},
    ],
    "proposed_action": {"response_action": "disable_account", "playbook_step_id": "T1685.005-3"},
}


def test_good_output_passes():
    assert check(GOOD, ALERT, [PLAYBOOK]) == []


def test_schema_violation():
    bad = dict(GOOD, severity="extreme")
    assert check(bad, ALERT, [PLAYBOOK])[0].startswith("schema:")


def test_invented_field_and_step():
    bad = copy.deepcopy(GOOD)
    bad["cited_fields"].append("IpAddress")
    bad["steps"].append({"action": "Reboot.", "playbook_step_id": "T1685.005-9"})
    problems = check(bad, ALERT, [PLAYBOOK])
    assert any("IpAddress" in p for p in problems)
    assert any("T1685.005-9" in p for p in problems)


def test_action_must_match_its_step():
    bad = copy.deepcopy(GOOD)
    bad["proposed_action"]["response_action"] = "block_ip"
    assert any("does not allow" in p for p in check(bad, ALERT, [PLAYBOOK]))


def test_action_step_must_be_in_steps():
    bad = copy.deepcopy(GOOD)
    bad["proposed_action"]["playbook_step_id"] = "T1685.005-4"
    bad["proposed_action"]["response_action"] = "isolate_host"
    assert any("not among" in p for p in check(bad, ALERT, [PLAYBOOK]))


def test_no_playbook_condition():
    out = copy.deepcopy(GOOD)
    for s in out["steps"]:
        s["playbook_step_id"] = None
    out["proposed_action"]["playbook_step_id"] = None
    assert check(out, ALERT, []) == []
