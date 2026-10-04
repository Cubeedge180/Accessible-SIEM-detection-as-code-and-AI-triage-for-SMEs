# Rule tests

Every rule in `rules/` needs a folder here named after the rule file (without `.yml`):

```
rules/tests/<rule_name>/positive.json   # events the rule MUST match
rules/tests/<rule_name>/negative.json   # events the rule must NOT match
```

Each file is a JSON array of events with at least one entry. CI fails if a rule
has no tests, a positive event is missed, or a negative event fires.
Keys starting with `_` (such as `_comment`) are ignored by the matcher.

Events currently use Sigma's native field names. They move to the normalized
schema once `normalize/` defines it.

Run locally with `pytest tests/test_rules.py`.
