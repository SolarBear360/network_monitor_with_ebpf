#!/usr/bin/env python3
"""evaluate_model_policy.py 的小型單元測試。"""

from __future__ import annotations

import unittest

import pandas as pd

from ml_test.evaluate_model_policy import Policy, apply_policy, evaluate


def make_rows(
    probabilities: list[float],
    syn_counts: list[int],
    labels: list[int] | None = None,
    timestamps: list[str] | None = None,
    sequence_id: str = "sequence-a",
) -> pd.DataFrame:
    """建立只包告警規則所需欄位的可控測試資料。"""
    size = len(probabilities)
    if labels is None:
        labels = [0] * size
    if timestamps is None:
        timestamps = pd.date_range(
            "2026-01-01T00:00:00Z", periods=size, freq="s"
        ).astype(str).tolist()
    return pd.DataFrame(
        {
            "dataset": ["unit_test"] * size,
            "source": ["synthetic"] * size,
            "sequence_id": [sequence_id] * size,
            "timestamp": timestamps,
            "timestamp_parsed": pd.to_datetime(timestamps, utc=True),
            "scenario": ["controlled"] * size,
            "label": labels,
            "tcp_packets": [max(value, 1) for value in syn_counts],
            "tcp_bytes": [60 * max(value, 1) for value in syn_counts],
            "syn_only_packets": syn_counts,
            "syn_ratio": [
                syn / max(total, 1)
                for syn, total in zip(
                    syn_counts, [max(value, 1) for value in syn_counts]
                )
            ],
            "attack_probability": probabilities,
        }
    )


class ApplyPolicyTests(unittest.TestCase):
    def test_minimum_syn_guard_blocks_low_volume_high_probability(self) -> None:
        data = make_rows([0.99, 0.99, 0.99], [1, 4, 5])
        result = apply_policy(data, Policy(0.5, 5, 1, 1))
        self.assertEqual(result["predicted_label"].tolist(), [0, 0, 1])

    def test_two_of_three_requires_two_candidate_seconds(self) -> None:
        data = make_rows([0.9, 0.9, 0.1, 0.9], [10, 10, 10, 10])
        result = apply_policy(data, Policy(0.5, 5, 2, 3))
        self.assertEqual(result["candidate"].astype(int).tolist(), [1, 1, 0, 1])
        self.assertEqual(result["predicted_label"].tolist(), [0, 1, 1, 1])

    def test_time_gap_resets_persistence_window(self) -> None:
        timestamps = [
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:01Z",
            "2026-01-01T00:00:10Z",
        ]
        data = make_rows([0.9, 0.9, 0.9], [10, 10, 10], timestamps=timestamps)
        result = apply_policy(data, Policy(0.5, 5, 2, 3))
        self.assertEqual(result["predicted_label"].tolist(), [0, 1, 0])

    def test_sequences_do_not_share_history(self) -> None:
        first = make_rows([0.9], [10], sequence_id="sequence-a")
        second = make_rows([0.9], [10], sequence_id="sequence-b")
        result = apply_policy(
            pd.concat([first, second], ignore_index=True), Policy(0.5, 5, 2, 3)
        )
        self.assertEqual(result["predicted_label"].tolist(), [0, 0])


class MetricTests(unittest.TestCase):
    def test_confusion_matrix_and_attack_events(self) -> None:
        data = make_rows(
            [0.1, 0.9, 0.9, 0.1],
            [0, 10, 10, 0],
            labels=[0, 0, 1, 1],
        )
        policy = Policy(0.5, 5, 1, 1)
        result = apply_policy(data, policy)
        metrics = evaluate(result, policy, "unit_test")
        self.assertEqual(metrics["true_negative"], 1)
        self.assertEqual(metrics["false_positive"], 1)
        self.assertEqual(metrics["false_negative"], 1)
        self.assertEqual(metrics["true_positive"], 1)
        self.assertEqual(metrics["attack_events"], 1)
        self.assertEqual(metrics["detected_attack_events"], 1)
        self.assertEqual(metrics["mean_detection_delay_seconds"], 0.0)


if __name__ == "__main__":
    unittest.main()
