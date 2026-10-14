# triage/

Local LLM triage through Ollama. Each alert gets an explanation, a severity, a
true/false-positive assessment, remediation steps and at most one proposed
response action, as JSON matching [output_schema.json](output_schema.json).

- `normalise_text.py`: turns an alert into one standard text form (experiment
  conditions C3 and C4). Deterministic code, no model.
- `playbooks.py`: loads and checks the playbooks in [../playbooks/](../playbooks/)
  (conditions C2 and C4).
- `validate_output.py`: schema check plus the automatic grounding checks (cited
  fields exist in the alert, cited step ids exist in the given playbooks, the
  proposed action is allowed by a cited step).
- `prompts/`: versioned prompts (to come).

The model only proposes. A proposed action goes to the approval queue in
`response/` and runs only after a person approves it.

The experiment design is in [docs/thesis/research-design.md](../docs/thesis/research-design.md).
