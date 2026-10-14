import csv
import random

import pytest

from eval.blind import RATING_COLUMNS, blind
from eval.score_triage import load, score


def _records(n_alerts=40):
    return [
        {"alert_id": f"A{a}", "condition": c, "run": run, "output": {"n": a}}
        for a in range(n_alerts)
        for c in ("C1", "C2", "C3", "C4")
        for run in (1, 2)
    ]


def test_blind_hides_condition_and_keeps_one_run():
    blinded, key = blind(_records(), seed=1, run=1)
    assert len(blinded) == 160
    assert all(set(b) == {"output_id", "alert_id", "output"} for b in blinded)
    assert {k["run"] for k in key} == {1}
    assert len({b["output_id"] for b in blinded}) == 160


def _write(tmp_path, effect: bool):
    _, key = blind(_records(), seed=1, run=1)
    rng = random.Random(2)
    with (tmp_path / "key.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["output_id", "alert_id", "condition", "run"])
        w.writeheader()
        w.writerows(key)
    with (tmp_path / "ratings.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["output_id", *RATING_COLUMNS])
        for k in key:
            normalised = k["condition"] in ("C3", "C4")
            playbook = k["condition"] in ("C2", "C4")
            p_halluc = 0.1 if effect and normalised else 0.5
            steps = 0.9 if effect and playbook else 0.5
            w.writerow([k["output_id"], 1, int(rng.random() < p_halluc), steps, 1, 0])
    return load(tmp_path / "key.csv", tmp_path / "ratings.csv")


def test_effects_are_detected(tmp_path):
    result = score(_write(tmp_path, effect=True))
    assert result["hypotheses"]["H1"]["supported"]
    assert result["hypotheses"]["H1"]["mean_difference"] < 0
    assert result["hypotheses"]["H2"]["supported"]


def test_no_effect_is_not_supported(tmp_path):
    result = score(_write(tmp_path, effect=False))
    assert not result["hypotheses"]["H2"]["supported"]
    assert result["hypotheses"]["H2"]["p_value"] == 1.0


def test_missing_rating_is_an_error(tmp_path):
    _write(tmp_path, effect=False)
    rows = (tmp_path / "ratings.csv").read_text().splitlines()
    (tmp_path / "ratings.csv").write_text("\n".join(rows[:-1]) + "\n")
    with pytest.raises(ValueError, match="no rating"):
        load(tmp_path / "key.csv", tmp_path / "ratings.csv")
