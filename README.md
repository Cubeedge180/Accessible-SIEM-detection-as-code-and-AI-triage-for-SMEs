# Accessible SIEM: detection-as-code and AI triage for SMEs

A lightweight SIEM for small and medium-sized enterprises that cannot afford
Splunk-class tools and have no dedicated SOC.

- **Easy to install:** one agent per host, one `docker compose up` for the server.
- **Detection as code:** Sigma rules versioned in Git, each with positive and
  negative test events, linted and tested in CI.
- **Private AI triage:** a locally hosted LLM (Ollama) explains each alert and
  suggests remediation. No data leaves the network.
- **Human in the loop:** response actions (block IP, disable account) are only
  proposed; nothing runs without explicit approval.

The project is also the practical part of a bachelor thesis, so every
experiment is recorded and reproducible, and results are compared against a
Wazuh baseline.

> Status: early skeleton. Only the rule pipeline (lint + tests) and an ingest
> health endpoint exist so far.

## Scope (MVP)

- Log sources: Windows (Sysmon, Security), Linux (auditd, auth.log), network
  (Suricata EVE JSON), web (ModSecurity audit logs).
- Ingestion API, normalization to an ECS-like schema, storage and search.
- Sigma engine producing alerts tagged with MITRE ATT&CK techniques.
- Dashboard: alert list, alert detail, ATT&CK coverage.
- LLM triage: explanation, severity, remediation, validated against a JSON schema.
- SOAR-lite: proposed actions executed only after approval (dashboard or Telegram).
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
triage/      local LLM client, versioned prompts, output schema
response/    SOAR-lite actions and approval flow
ui/          dashboard
lab/         isolated lab setup and attack playbooks
eval/        test harness, metrics, raw results in eval/results/
docs/        architecture, decision log (docs/decisions/), thesis notes
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
3. Run `python -m detect.lint && pytest`. CI runs the same checks on every pull request.
