# eval/

Test harness, metrics and thesis analysis. Raw outputs of every run go in
`results/`, with the command, date and commit hash, so every number in the
thesis can be rebuilt.

Triage experiment (RQ2 in [docs/thesis/research-design.md](../docs/thesis/research-design.md)):

```sh
python -m eval.blind outputs.jsonl eval/results/<run>/    # hide conditions, make rating sheet
# rate eval/results/<run>/ratings.csv by hand, without opening key.csv
python -m eval.score_triage eval/results/<run>/key.csv eval/results/<run>/ratings.csv \
    eval/results/<run>/scores.json
```

- `triage_set/`: the labelled alert set and reference labels (to come).
- Feasibility scorecard (RQ1) and attack-run metrics (MTTD, MTTA, detection
  rate, FP rate): to come.
