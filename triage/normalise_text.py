"""Turn an alert into one standard text form before the LLM sees it.

This is the "normalised text" input of the triage experiment (conditions C3 and
C4 in docs/thesis/research-design.md), after Danho (KTH 2026). It is plain code,
not a model: the same alert always gives the same text.

The text carries the same facts as the raw alert JSON, only in a fixed order and
wording. Fields the template does not name are listed under "Other fields", so
the experiment compares form, not amount of information. Each line names the
event field(s) it came from in brackets, so the model can cite them and
triage.validate_output can check the citations.

Alert shape:
    {"alert_id": str, "created_at": str,
     "rule": {"id": str, "title": str, "level": str, "tags": [str], "description": str?},
     "event": {...}}
"""

from __future__ import annotations

import re
from typing import Any

Alert = dict[str, Any]

# (label, candidate event fields). The first field present wins. Sigma-native
# Windows names come first while normalize/ has no common schema yet; ECS-style
# names follow so the same template keeps working after normalisation.
FIELDS: list[tuple[str, list[str]]] = [
    ("Event time", ["TimeCreated", "@timestamp", "timestamp"]),
    ("Host", ["Computer", "host.name", "hostname"]),
    ("Event ID", ["EventID", "event.code"]),
    ("Process", ["Image", "NewProcessName", "process.executable"]),
    ("Command line", ["CommandLine", "process.command_line"]),
    ("Parent process", ["ParentImage", "process.parent.executable"]),
    ("Source IP", ["IpAddress", "SourceIp", "source.ip", "src_ip"]),
    ("Destination IP", ["DestinationIp", "destination.ip", "dest_ip"]),
    ("Destination port", ["DestinationPort", "destination.port", "dest_port"]),
]

# Users are written DOMAIN\name when both parts exist.
USER_FIELDS: list[tuple[str | None, str]] = [
    ("SubjectDomainName", "SubjectUserName"),
    ("TargetDomainName", "TargetUserName"),
    (None, "User"),
    (None, "user.name"),
]

TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
GROUP_OR_SOFTWARE_TAG = re.compile(r"^attack\.[gs]\d{4}$", re.IGNORECASE)
NONE = "none recorded"


def get_field(event: dict[str, Any], key: str) -> Any:
    """Look up a field by flat key or by dotted path into nested dicts."""
    if key in event:
        return event[key]
    node: Any = event
    for part in key.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def flatten(event: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Nested dicts as dotted keys, so every leaf field has one citable name."""
    flat: dict[str, Any] = {}
    for key, value in event.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(flatten(value, f"{name}."))
        else:
            flat[name] = value
    return flat


def attack_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    """Split Sigma tags into ATT&CK technique ids and tactic names."""
    techniques, tactics = [], []
    for tag in tags:
        if m := TECHNIQUE_TAG.match(tag):
            techniques.append(m.group(1).upper())
        elif tag.lower().startswith("attack.") and not GROUP_OR_SOFTWARE_TAG.match(tag):
            tactics.append(tag.split(".", 1)[1])
    return techniques, tactics


def _present(value: Any) -> bool:
    return value is not None and value != ""


def normalise(alert: Alert) -> str:
    rule = alert["rule"]
    event = alert["event"]
    flat = flatten(event)
    used: set[str] = set()
    techniques, tactics = attack_tags(rule.get("tags", []))

    lines = [
        f"Alert {alert['alert_id']} created {alert.get('created_at', NONE)}.",
        f"Rule: {rule['title']} (rule id {rule['id']}, level {rule.get('level', NONE)}).",
        f"ATT&CK technique: {', '.join(techniques) or NONE}; tactic: {', '.join(tactics) or NONE}.",
    ]
    if rule.get("description"):
        lines.append(f"Rule description: {' '.join(str(rule['description']).split())}")

    for label, candidates in FIELDS:
        key = next((k for k in candidates if _present(get_field(event, k))), None)
        if key is None:
            lines.append(f"{label}: {NONE}.")
        else:
            used.add(key)
            lines.append(f"{label} [{key}]: {get_field(event, key)}.")

    lines.append(_user_line(event, used))

    other = {k: v for k, v in sorted(flat.items()) if k not in used and _present(v)}
    if other:
        lines.append("Other fields: " + "; ".join(f"[{k}] {v}" for k, v in other.items()) + ".")
    return "\n".join(lines)


def _user_line(event: dict[str, Any], used: set[str]) -> str:
    for domain_key, name_key in USER_FIELDS:
        name = get_field(event, name_key)
        if not _present(name):
            continue
        domain = get_field(event, domain_key) if domain_key else None
        if _present(domain):
            used.update({domain_key, name_key})
            return f"User [{domain_key}, {name_key}]: {domain}\\{name}."
        used.add(name_key)
        return f"User [{name_key}]: {name}."
    return f"User: {NONE}."
