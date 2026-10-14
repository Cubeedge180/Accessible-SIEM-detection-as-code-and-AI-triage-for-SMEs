# Accessible SIEM: detection-as-code and local AI triage

A lightweight SIEM for organisations that cannot afford Splunk-class tools and
have no dedicated SOC.

- **Easy to install:** one agent per host, one `docker compose up` for the server.
- **Detection as code:** Sigma rules versioned in Git, each with positive and
  negative test events, linted and tested in CI.
- **Private AI triage:** a locally hosted LLM (Ollama) explains each alert and
  suggests remediation. No data leaves the network.
- **Human in the loop:** response actions (block IP, disable account) are only
  proposed; nothing runs without explicit approval.

The project is also the practical part of a bachelor thesis, *Feasibility of an Open-Source SIEM: A Comparative Study with Wazuh and Local LLM Triage*, so every
experiment is recorded and reproducible, and results are compared against a
Wazuh baseline.

> Status: early skeleton. The rule pipeline (lint + tests), an ingest health
> endpoint, the remediation playbooks and the triage experiment tooling
> (alert-to-text normaliser, output checks, blinding and scoring) exist so far.

## What the thesis tests

The [research design](docs/thesis/research-design.md) fixes the questions,
thresholds and analysis before any final measurement:

- **RQ1, feasibility:** can an organisation without a dedicated SOC run this system? Answered with
  a scorecard of criteria (install effort, hardware, detection, noise, speed,
  privacy, cost), each with a pass threshold, compared against Wazuh.
- **RQ2, grounding:** do alerts normalised to one text form, and
  machine-structured playbooks in the prompt, make the local LLM's triage
  less hallucinated and more correct? A 2 x 2 experiment on a hand-labelled
  alert set.

## Scope (MVP)

- Log sources: Windows (Sysmon, Security), Linux (auditd, auth.log), network
  (Suricata EVE JSON). Web (ModSecurity audit logs) is optional.
- Ingestion API, normalization to an ECS-like schema, storage and search.
- Sigma engine producing alerts tagged with MITRE ATT&CK techniques.
- Dashboard: alert list, alert detail, ATT&CK coverage.
- LLM triage: explanation, severity, remediation, validated against a JSON schema.
- SOAR-lite: proposed actions from playbooks, executed only after approval in the dashboard.
- Test harness measuring MTTD, MTTA, MTTR, detection rate and false positive rate.

Out of scope: multi-tenancy, HA clustering, and any testing against systems the
author does not own. Attack simulation runs only inside the isolated lab.

## Repository layout

```
agent/       shipper configs and per-host installer
ingest/      ingestion API (FastAPI)
normalize/   parsers and the common event schema
detect/      Sigma evaluator, rule linting, alert builder
rules/       Sigma rules, one folder per ATT&CK tactic
rules/tests/ positive and negative test events per rule
triage/      local LLM client, alert-to-text normaliser, prompts, output schema
playbooks/   remediation playbooks, one YAML file per ATT&CK technique
response/    SOAR-lite actions and approval flow
ui/          dashboard
lab/         isolated lab setup and attack playbooks
eval/        test harness, metrics, raw results in eval/results/
docs/        architecture, decision log (docs/decisions/), thesis design (docs/thesis/)
```

## Quick start

Server stack:

```sh
cp .env.example .env
docker compose up -d              # ingest API on http://localhost:8000/health
docker compose --profile llm up -d   # also start Ollama for triage
```

Development:

```sh
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m detect.lint     # validate all Sigma rules
pytest                    # rule tests and unit tests
```

## Writing a rule

1. Add the rule to `rules/<attack_tactic>/<rule_name>.yml` with ATT&CK tags.
2. Add `rules/tests/<rule_name>/positive.json` and `negative.json`, each a JSON
   array of events (see [rules/tests/README.md](rules/tests/README.md)).
3. Add `playbooks/<technique>.yml` for any ATT&CK technique that has no
   playbook yet (see [playbooks/README.md](playbooks/README.md)).
4. Run `python -m detect.lint && pytest`. CI runs the same checks on every pull request.
