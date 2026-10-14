"""Playbooks must be valid and cover every ATT&CK technique a rule is tagged with."""

from pathlib import Path

import pytest

from detect.evaluator import load_rule
from detect.lint import rule_files
from triage.normalise_text import attack_tags
from triage.playbooks import load, load_all, playbook_files, problems

FILES = playbook_files()


def test_playbooks_exist():
    assert FILES


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_playbook_valid(path: Path):
    assert problems(load(path), path.name) == []


def test_every_rule_technique_has_a_playbook():
    techniques = load_all()
    for rule_path in rule_files():
        tags = [str(t) for t in load_rule(rule_path).tags]
        for technique in attack_tags(tags)[0]:
            assert technique in techniques, f"{rule_path.name}: no playbook for {technique}"


def test_destructive_step_without_approval_is_rejected():
    playbook = load(FILES[0])
    step = next(s for s in playbook["steps"] if s["destructive"])
    step["requires_approval"] = False
    assert any("requires_approval" in p for p in problems(playbook, FILES[0].name))
