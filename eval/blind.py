"""Hide which experiment condition produced each triage output before rating.

Usage: python -m eval.blind <outputs.jsonl> <out_dir> [--seed N] [--run 1]

<outputs.jsonl> has one record per model output:
    {"alert_id": str, "condition": "C1".."C4", "run": int, "output": {...}}

Writes to <out_dir>:
    blinded.jsonl   records in shuffled order with a random output_id and no
                    condition or run, for the rater
    ratings.csv     empty rating sheet, one row per blinded output
    key.csv         output_id -> alert_id, condition, run (do not open before
                    rating is finished)

Only one run (default 1) is rated by hand; the other runs exist to check that
outputs are stable at temperature 0.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from pathlib import Path

CONDITIONS = {"C1", "C2", "C3", "C4"}
RATING_COLUMNS = ["grounded", "hallucinated", "steps_correct", "severity_agree", "unsafe"]


def blind(records: list[dict], seed: int, run: int) -> tuple[list[dict], list[dict]]:
    chosen = [r for r in records if r["run"] == run]
    for r in chosen:
        if r["condition"] not in CONDITIONS:
            raise ValueError(f"unknown condition {r['condition']!r}")
    rng = random.Random(seed)
    rng.shuffle(chosen)
    ids = rng.sample(range(10_000, 100_000), len(chosen))
    blinded, key = [], []
    for output_id, r in zip((f"O{i}" for i in ids), chosen, strict=True):
        blinded.append({"output_id": output_id, "alert_id": r["alert_id"], "output": r["output"]})
        key.append(
            {
                "output_id": output_id,
                "alert_id": r["alert_id"],
                "condition": r["condition"],
                "run": r["run"],
            }
        )
    return blinded, key


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("outputs", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--seed", type=int, default=20261014)
    parser.add_argument("--run", type=int, default=1)
    args = parser.parse_args(argv)

    lines = args.outputs.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines if line.strip()]
    blinded, key = blind(records, args.seed, args.run)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    with (args.out_dir / "blinded.jsonl").open("w", encoding="utf-8") as f:
        f.writelines(json.dumps(b, ensure_ascii=False) + "\n" for b in blinded)
    with (args.out_dir / "ratings.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["output_id", *RATING_COLUMNS])
        writer.writerows([b["output_id"]] + [""] * len(RATING_COLUMNS) for b in blinded)
    with (args.out_dir / "key.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["output_id", "alert_id", "condition", "run"])
        writer.writeheader()
        writer.writerows(key)
    print(f"{len(blinded)} outputs blinded into {args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
