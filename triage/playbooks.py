"""Load and check the remediation playbooks in playbooks/."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent / "playbooks"
SCHEMA = json.loads((PLAYBOOKS_DIR / "schema.json").read_text(encoding="utf-8"))

Playbook = dict[str, Any]


def playbook_files(playbooks_dir: Path = PLAYBOOKS_DIR) -> list[Path]:
    return sorted(playbooks_dir.glob("T*.yml"))


def load(path: Path) -> Playbook:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_all(playbooks_dir: Path = PLAYBOOKS_DIR) -> dict[str, Playbook]:
    """Playbooks keyed by technique id."""
    return {p.stem: load(p) for p in playbook_files(playbooks_dir)}


def problems(playbook: Playbook, filename: str) -> list[str]:
    """Schema errors plus the rules the schema cannot express."""
    found = [
        f"{filename}: {e.json_path}: {e.message}"
        for e in Draft202012Validator(SCHEMA).iter_errors(playbook)
    ]
    if found:
        return found
    technique = playbook["technique"]
    if Path(filename).stem != technique:
        found.append(f"{filename}: file name must be {technique}.yml")
    ids = [s["id"] for s in playbook["steps"]]
    if len(ids) != len(set(ids)):
        found.append(f"{filename}: step ids must be unique")
    for step in playbook["steps"]:
        if not step["id"].startswith(f"{technique}-"):
            found.append(f"{filename}: step {step['id']} must start with {technique}-")
        risky = step["destructive"] or "response_action" in step
        if risky and not step.get("requires_approval"):
            found.append(
                f"{filename}: step {step['id']} changes the system, so it must have "
                "requires_approval: true"
            )
    return found


def steps_by_id(playbooks: list[Playbook]) -> dict[str, dict[str, Any]]:
    return {s["id"]: s for pb in playbooks for s in pb["steps"]}
