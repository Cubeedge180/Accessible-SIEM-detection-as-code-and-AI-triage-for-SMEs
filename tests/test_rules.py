"""Every Sigma rule must match its positive events and none of its negative events."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from detect.evaluator import load_rule, matches
from detect.lint import RULES_DIR, rule_files

TESTS_DIR = RULES_DIR / "tests"
RULES = rule_files()


def _events(rule: Path, kind: str) -> list[dict]:
    path = TESTS_DIR / rule.stem / f"{kind}.json"
    assert path.is_file(), f"{rule.relative_to(RULES_DIR)} is missing {path.relative_to(RULES_DIR)}"
    events = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(events, list) and events, f"{path} must be a non-empty JSON array"
    return [{k: v for k, v in e.items() if not k.startswith("_")} for e in events]


def _id(rule: Path) -> str:
    return rule.stem


def test_rules_exist():
    assert RULES, "no Sigma rules found"


def test_rule_names_unique():
    stems = [r.stem for r in RULES]
    assert len(stems) == len(set(stems)), "rule file names must be unique across tactic folders"


@pytest.mark.parametrize("rule_path", RULES, ids=_id)
def test_positive_events_match(rule_path: Path):
    rule = load_rule(rule_path)
    for i, event in enumerate(_events(rule_path, "positive")):
        assert matches(rule, event), f"positive event #{i} did not match"


@pytest.mark.parametrize("rule_path", RULES, ids=_id)
def test_negative_events_do_not_match(rule_path: Path):
    rule = load_rule(rule_path)
    for i, event in enumerate(_events(rule_path, "negative")):
        assert not matches(rule, event), f"negative event #{i} matched"
