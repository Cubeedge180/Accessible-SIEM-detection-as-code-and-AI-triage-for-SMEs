"""Check one LLM triage output against the schema and against what it was given.

The automatic part of the grounding score in docs/thesis/research-design.md:
an output fails a check if it cites an event field the alert does not have,
cites a playbook step that was not in the prompt, or proposes an action that no
cited step allows. The human rater scores the rest (claims in the free-text
explanation, step correctness).

None of these checks runs an action. A valid proposed_action only goes to the
approval queue, where a person decides.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from triage.normalise_text import flatten
from triage.playbooks import Playbook, steps_by_id

SCHEMA = json.loads(
    (Path(__file__).resolve().parent / "output_schema.json").read_text(encoding="utf-8")
)


def check(output: Any, alert: dict[str, Any], playbooks: list[Playbook]) -> list[str]:
    """Problems with the output; an empty list means it passed every check.

    playbooks is what the prompt contained: empty in conditions C1 and C3.
    """
    errors = [
        f"schema: {e.json_path}: {e.message}"
        for e in Draft202012Validator(SCHEMA).iter_errors(output)
    ]
    if errors:
        return errors

    problems = []
    if output["alert_id"] != alert["alert_id"]:
        problems.append(f"alert_id {output['alert_id']!r} is not {alert['alert_id']!r}")

    fields = set(flatten(alert["event"]))
    for name in output["cited_fields"]:
        if name not in fields:
            problems.append(f"cited field {name!r} is not in the alert")

    known = steps_by_id(playbooks)
    cited = set()
    for step in output["steps"]:
        step_id = step["playbook_step_id"]
        if step_id is None:
            continue
        if step_id not in known:
            problems.append(f"step id {step_id!r} is not in the given playbooks")
        cited.add(step_id)

    action = output["proposed_action"]
    if action is not None and playbooks:
        step_id = action["playbook_step_id"]
        if step_id not in known:
            problems.append(f"proposed action cites unknown step {step_id!r}")
        elif step_id not in cited:
            problems.append(f"proposed action step {step_id!r} is not among the output's steps")
        elif known[step_id].get("response_action") != action["response_action"]:
            problems.append(f"step {step_id!r} does not allow {action['response_action']!r}")
    return problems
