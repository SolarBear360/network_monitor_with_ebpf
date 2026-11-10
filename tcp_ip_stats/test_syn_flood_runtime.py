#!/usr/bin/env python3

import unittest
from pathlib import Path

from syn_flood_runtime import LogisticRuntimeModel, SynFloodDetector


ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "model_handoff" / "syn-window-v1" / "runtime_model.json"


class SynFloodRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.detector = SynFloodDetector.load(MODEL_PATH)

    def evaluate(self, packets, byte_count, syn, seconds=1.0):
        return self.detector.evaluate(
            tcp_packets=packets,
            tcp_bytes=byte_count,
            syn_only_packets=syn,
            interval_seconds=seconds,
        )

    def test_one_syn_never_becomes_candidate(self):
        result = self.evaluate(2, 120, 1)
        self.assertFalse(result.candidate)
        self.assertEqual(result.status, "NORMAL")

    def test_two_of_three_enters_attack(self):
        first = self.evaluate(100, 8000, 35)
        second = self.evaluate(100, 8000, 35)
        self.assertEqual(first.status, "SUSPECT")
        self.assertEqual(second.status, "ATTACK")

    def test_three_normal_windows_clear_attack(self):
        self.evaluate(100, 8000, 35)
        self.evaluate(100, 8000, 35)
        self.assertEqual(self.evaluate(80, 7000, 5).status, "ATTACK")
        self.assertEqual(self.evaluate(80, 7000, 5).status, "ATTACK")
        self.assertEqual(self.evaluate(80, 7000, 5).status, "NORMAL")

    def test_invalid_duration_does_not_change_state(self):
        invalid = self.evaluate(100, 8000, 35, seconds=0.2)
        self.assertEqual(invalid.status, "INSUFFICIENT_DATA")
        self.assertEqual(invalid.recent_window_size, 0)

    def test_probability_is_bounded(self):
        model = LogisticRuntimeModel.load(MODEL_PATH)
        for values in [(0, 0, 0), (2, 120, 1), (100, 8000, 35)]:
            probability = model.predict_probability(*values)
            self.assertGreaterEqual(probability, 0.0)
            self.assertLessEqual(probability, 1.0)


if __name__ == "__main__":
    unittest.main()
