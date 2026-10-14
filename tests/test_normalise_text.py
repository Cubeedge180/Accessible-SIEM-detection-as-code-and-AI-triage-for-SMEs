import json
from pathlib import Path

from triage.normalise_text import attack_tags, flatten, normalise

EVENT = json.loads(
    Path("rules/tests/win_security_log_cleared/positive.json").read_text(encoding="utf-8")
)[0]
ALERT = {
    "alert_id": "A-0001",
    "created_at": "2026-10-04T12:00:05Z",
    "rule": {
        "id": "6f1c2d9e-8b4a-4f3e-9c71-2a5d0e8b7c41",
        "title": "Windows Security Event Log Cleared",
        "level": "high",
        "tags": ["attack.defense-impairment", "attack.t1685.005"],
    },
    "event": EVENT,
}


def test_attack_tags():
    tags = ["attack.defense-impairment", "attack.t1685.005", "attack.T1110", "attack.g0016"]
    assert attack_tags(tags) == (["T1685.005", "T1110"], ["defense-impairment"])


def test_known_fields_are_labelled_with_their_source():
    text = normalise(ALERT)
    assert "ATT&CK technique: T1685.005; tactic: defense-impairment." in text
    assert "Host [Computer]: WIN-LAB01.lab.local." in text
    assert "User [SubjectDomainName, SubjectUserName]: LAB\\labadmin." in text
    assert "Source IP: none recorded." in text


def test_no_event_value_is_lost():
    text = normalise(ALERT)
    for key, value in flatten(EVENT).items():
        assert str(value) in text, f"{key} missing from normalised text"


def test_deterministic_and_order_independent():
    reordered = dict(ALERT, event=dict(reversed(list(EVENT.items()))))
    assert normalise(ALERT) == normalise(reordered)


def test_nested_ecs_fields():
    alert = dict(ALERT, event={"host": {"name": "srv1"}, "user": {"name": "bob"}, "x": 1})
    text = normalise(alert)
    assert "Host [host.name]: srv1." in text
    assert "User [user.name]: bob." in text
    assert "Other fields: [x] 1." in text
