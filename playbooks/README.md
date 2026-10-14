# Remediation playbooks

One YAML file per ATT&CK technique, named by technique id (`T1110.001.yml`) and
validated against [schema.json](schema.json) in CI. They are given to the
triage LLM in conditions C2 and C4 of the experiment
([research design](../docs/thesis/research-design.md)).

The format is structured for the machine, after Nyman (Halmstad 2026): short,
labelled fields and a stable id per step, so the model picks and cites steps
instead of writing its own, and a script can check what it cited.

Rules checked by `tests/test_playbooks.py`:

- Every ATT&CK technique tagged on a Sigma rule in `rules/` has a playbook.
- Step ids are `<technique>-<n>` and unique.
- A step with `destructive: true` or a `response_action` must have
  `requires_approval: true`. The model can only propose these; nothing runs
  until a person approves it in the dashboard.
