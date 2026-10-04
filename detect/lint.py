"""Lint every Sigma rule under rules/ with pySigma's built-in validators.

Usage: python -m detect.lint [rules_dir]
Exits non-zero if any rule fails to parse or any validator reports an issue.

The ATT&CK tag validator downloads MITRE's ATT&CK data from GitHub. Set
SIGMA_LINT_OFFLINE=1 to skip it when working without network access; CI always
runs it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.validation import SigmaValidator
from sigma.validators.core import validators

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

# D3FEND tags are not used in this project and its validator needs network access.
SKIPPED = {"d3_fendtag"}
SKIPPED_OFFLINE = {"attacktag"}


def rule_files(rules_dir: Path = RULES_DIR) -> list[Path]:
    """All Sigma rule files, excluding test fixtures."""
    return sorted(
        p for p in rules_dir.rglob("*.yml") if "tests" not in p.relative_to(rules_dir).parts
    )


def main(argv: list[str]) -> int:
    rules_dir = Path(argv[1]) if len(argv) > 1 else RULES_DIR
    files = rule_files(rules_dir)
    if not files:
        print(f"no rules found under {rules_dir}")
        return 1

    collection = SigmaCollection.load_ruleset([str(p) for p in files], collect_errors=True)
    problems = [f"{e.source}: {e}" for e in collection.errors]
    for rule in collection.rules:
        problems += [f"{e.source}: {e}" for e in rule.errors]

    skipped = SKIPPED | (SKIPPED_OFFLINE if os.environ.get("SIGMA_LINT_OFFLINE") else set())
    validator = SigmaValidator(v for name, v in validators.items() if name not in skipped)
    problems += [str(issue) for issue in validator.validate_rules(collection)]

    for p in problems:
        print(p)
    print(f"{len(files)} rule(s) checked, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
