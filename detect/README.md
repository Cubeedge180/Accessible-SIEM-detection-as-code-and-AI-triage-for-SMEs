# detect/

Sigma detection engine.

- `evaluator.py` evaluates a Sigma rule directly against an event dict, using the
  condition tree pySigma parses. Unsupported Sigma features raise
  `NotImplementedError` rather than silently not matching.
- `lint.py` parses every rule under `rules/` and runs pySigma's validators
  (`python -m detect.lint`).

Still to come: rule loader for the live pipeline, logsource routing, alert builder.
