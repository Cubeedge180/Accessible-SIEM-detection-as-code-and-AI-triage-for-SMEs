"""Score the 2 x 2 triage experiment from the blinded ratings.

Usage: python -m eval.score_triage <key.csv> <ratings.csv> <out.json>

Implements the analysis fixed in docs/thesis/research-design.md, section 4.5:

- For each alert and measure, the main effect of a factor is the mean over the
  two cells with the factor minus the mean over the two cells without it.
  Normalised text: (C3 + C4) / 2 - (C1 + C2) / 2.
  Playbook:        (C2 + C4) / 2 - (C1 + C3) / 2.
- H1: normalised text lowers the hallucination rate (one-sided, "less").
- H2: playbooks raise the share of correct steps (one-sided, "greater").
- Test: Wilcoxon signed-rank on the per-alert differences, zero differences
  dropped. Reported with the mean difference, a bootstrap 95% CI and the
  matched-pairs rank-biserial correlation as effect size.
- Every other measure x factor pair is reported two-sided as exploratory.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy.stats import rankdata, wilcoxon

MEASURES = {
    "grounded": "fraction",
    "hallucinated": "binary",
    "steps_correct": "fraction",
    "severity_agree": "binary",
    "unsafe": "binary",
}
FACTORS = {
    "normalised_text": (("C3", "C4"), ("C1", "C2")),
    "playbook": (("C2", "C4"), ("C1", "C3")),
}
HYPOTHESES = {
    "H1": ("normalised_text", "hallucinated", "less"),
    "H2": ("playbook", "steps_correct", "greater"),
}
ALPHA = 0.05
BOOTSTRAP_SAMPLES = 10_000
SEED = 20261014


def load(key_path: Path, ratings_path: Path) -> dict[str, dict[str, dict[str, float]]]:
    """Ratings as {alert_id: {condition: {measure: value}}}; raises on bad input."""
    with key_path.open(encoding="utf-8", newline="") as f:
        key = {row["output_id"]: row for row in csv.DictReader(f)}
    with ratings_path.open(encoding="utf-8", newline="") as f:
        ratings = list(csv.DictReader(f))

    data: dict[str, dict[str, dict[str, float]]] = defaultdict(dict)
    for row in ratings:
        output_id = row["output_id"]
        if output_id not in key:
            raise ValueError(f"{output_id} is not in the key")
        values = {}
        for measure, kind in MEASURES.items():
            raw = (row.get(measure) or "").strip()
            if not raw:
                raise ValueError(f"{output_id}: {measure} is not rated")
            value = float(raw)
            if not 0 <= value <= 1 or (kind == "binary" and value not in (0, 1)):
                raise ValueError(f"{output_id}: {measure}={raw} is out of range")
            values[measure] = value
        k = key[output_id]
        if k["condition"] in data[k["alert_id"]]:
            raise ValueError(f"{k['alert_id']} has two ratings for {k['condition']}")
        data[k["alert_id"]][k["condition"]] = values

    for alert_id, cells in data.items():
        missing = {"C1", "C2", "C3", "C4"} - set(cells)
        if missing:
            raise ValueError(f"{alert_id} has no rating for {sorted(missing)}")
    return dict(data)


def differences(data, factor: str, measure: str) -> np.ndarray:
    with_, without = FACTORS[factor]
    return np.array(
        [
            np.mean([cells[c][measure] for c in with_])
            - np.mean([cells[c][measure] for c in without])
            for _, cells in sorted(data.items())
        ]
    )


def test(d: np.ndarray, alternative: str) -> dict:
    rng = np.random.default_rng(SEED)
    boot = rng.choice(d, size=(BOOTSTRAP_SAMPLES, len(d)), replace=True).mean(axis=1)
    nonzero = d[d != 0]
    if len(nonzero) == 0:
        p, r = 1.0, 0.0
    else:
        p = float(wilcoxon(nonzero, alternative=alternative).pvalue)
        ranks = rankdata(np.abs(nonzero))
        r = float((ranks[nonzero > 0].sum() - ranks[nonzero < 0].sum()) / ranks.sum())
    return {
        "n_alerts": len(d),
        "n_nonzero": int(len(nonzero)),
        "mean_difference": float(d.mean()),
        "ci95": [float(np.percentile(boot, 2.5)), float(np.percentile(boot, 97.5))],
        "alternative": alternative,
        "p_value": p,
        "rank_biserial": r,
    }


def score(data) -> dict:
    cells = {
        c: {m: float(np.mean([a[c][m] for a in data.values()])) for m in MEASURES}
        for c in ("C1", "C2", "C3", "C4")
    }
    hypotheses = {}
    for name, (factor, measure, alternative) in HYPOTHESES.items():
        result = test(differences(data, factor, measure), alternative)
        result |= {"factor": factor, "measure": measure, "supported": result["p_value"] < ALPHA}
        hypotheses[name] = result
    primary = {(f, m) for f, m, _ in HYPOTHESES.values()}
    exploratory = [
        {"factor": f, "measure": m} | test(differences(data, f, m), "two-sided")
        for f in FACTORS
        for m in MEASURES
        if (f, m) not in primary
    ]
    return {
        "alpha": ALPHA,
        "cell_means": cells,
        "hypotheses": hypotheses,
        "exploratory": exploratory,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__.splitlines()[2])
        return 2
    result = score(load(Path(argv[0]), Path(argv[1])))
    Path(argv[2]).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for name, h in result["hypotheses"].items():
        verdict = "supported" if h["supported"] else "not supported"
        print(
            f"{name} ({h['factor']} -> {h['measure']}): mean diff {h['mean_difference']:+.3f}, "
            f"p={h['p_value']:.4f}, {verdict}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
