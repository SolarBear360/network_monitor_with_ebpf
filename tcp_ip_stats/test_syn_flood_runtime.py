#!/usr/bin/env python3

import unittest
import json
from pathlib import Path

from syn_flood_runtime import LogisticRuntimeModel, SynFloodDetector
from tcpip_stats import DEFAULT_RUNTIME_MODEL


ROOT = Path(__file__).resolve().parent
MODEL_PATH = (
    ROOT / "model_handoff" / "syn-window-full6-v1" / "runtime_model.json"
)
FULL6_FEATURES = [
    "tcp_packets",
    "tcp_bytes",
    "syn_only_packets",
    "syn_ratio",
    "active_source_ips",
    "established_connections",
]


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

    def test_project_default_is_the_full_six_feature_model(self):
        model = LogisticRuntimeModel.load(DEFAULT_RUNTIME_MODEL)
        self.assertEqual(DEFAULT_RUNTIME_MODEL, MODEL_PATH)
        self.assertEqual(model.features, FULL6_FEATURES)
        self.assertEqual(model.config["package_name"], "syn-window-full6-v1")

    def test_established_connections_feature_can_be_used(self):
        model = LogisticRuntimeModel.load(MODEL_PATH)

        without_handshake = model.predict_probability(100, 8000, 35, 0)
        with_handshake = model.predict_probability(100, 8000, 35, 10)

        self.assertLess(with_handshake, without_handshake)

    def test_active_source_ips_feature_can_be_used(self):
        model = LogisticRuntimeModel.load(MODEL_PATH)

        one_source = model.predict_probability(
            100, 8000, 35, active_source_ips=1
        )
        ten_sources = model.predict_probability(
            100, 8000, 35, active_source_ips=10
        )

        self.assertGreater(ten_sources, one_source)

    def test_active_ips_per_established_feature_can_be_used(self):
        config = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
        config["features"].append("active_ips_per_established_connection")
        config["imputer_median"].append(0.0)
        config["scaler_mean"].append(0.0)
        config["scaler_scale"].append(1.0)
        config["coefficient"].append(1.0)
        model = LogisticRuntimeModel(config)

        no_completed_connection = model.predict_probability(
            100,
            8000,
            35,
            established_connections=0,
            active_source_ips=10,
        )
        many_completed_connections = model.predict_probability(
            100,
            8000,
            35,
            established_connections=9,
            active_source_ips=10,
        )

        self.assertGreater(no_completed_connection, many_completed_connections)


if __name__ == "__main__":
    unittest.main()
