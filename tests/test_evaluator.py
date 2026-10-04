"""Unit tests for the Sigma evaluator, independent of the rule library."""

from __future__ import annotations

import pytest
from sigma.rule import SigmaRule

from detect.evaluator import matches


def rule(detection: str) -> SigmaRule:
    return SigmaRule.from_yaml("title: t\nlogsource: {product: test}\ndetection:\n" + detection)


def test_exact_match_is_case_insensitive():
    r = rule("  sel:\n    Image: C:\\Windows\\cmd.exe\n  condition: sel\n")
    assert matches(r, {"Image": "c:\\windows\\CMD.EXE"})
    assert not matches(r, {"Image": "C:\\Windows\\cmd.exe.bak"})


def test_modifiers():
    r = rule(
        "  sel:\n"
        "    CommandLine|contains|all: ['-enc', 'powershell']\n"
        "    Image|endswith: '.exe'\n"
        "  condition: sel\n"
    )
    assert matches(r, {"CommandLine": "PowerShell -Enc AAA", "Image": "p.exe"})
    assert not matches(r, {"CommandLine": "powershell -nop", "Image": "p.exe"})


def test_list_values_are_or():
    r = rule("  sel:\n    EventID: [4624, 4625]\n  condition: sel\n")
    assert matches(r, {"EventID": 4625})
    assert matches(r, {"EventID": "4624"})
    assert not matches(r, {"EventID": 4634})


def test_not_and_missing_fields():
    r = rule(
        "  sel:\n    EventID: 1\n  filter:\n    User: SYSTEM\n  condition: sel and not filter\n"
    )
    assert matches(r, {"EventID": 1, "User": "alice"})
    assert matches(r, {"EventID": 1})
    assert not matches(r, {"EventID": 1, "User": "system"})
    assert not matches(r, {"User": "alice"})


def test_null_and_one_of():
    r = rule("  sel_a:\n    Field: null\n  sel_b:\n    Other: x\n  condition: 1 of sel_*\n")
    assert matches(r, {"Other": "y"})
    assert matches(r, {"Field": "set", "Other": "x"})
    assert not matches(r, {"Field": "set", "Other": "y"})


def test_regex_and_cidr():
    r = rule(
        "  sel:\n    Query|re: '^[a-z0-9]{30,}\\.'\n    SourceIp|cidr: 10.0.0.0/8\n"
        "  condition: sel\n"
    )
    assert matches(r, {"Query": "a" * 32 + ".evil.test", "SourceIp": "10.1.2.3"})
    assert not matches(r, {"Query": "a" * 32 + ".evil.test", "SourceIp": "192.168.1.1"})


def test_unsupported_value_fails_loudly():
    r = rule("  sel:\n    Field|expand: '%placeholder%'\n  condition: sel\n")
    with pytest.raises(NotImplementedError):
        matches(r, {"Field": "x"})
