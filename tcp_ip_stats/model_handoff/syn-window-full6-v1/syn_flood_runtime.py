#!/usr/bin/env python3
"""SYN Flood 輕量推論與告警狀態機。

只使用 Python 標準函式庫，適合由需要 root 權限的 eBPF userspace
收集器直接呼叫，不需要在 root Python 安裝 scikit-learn。
"""

from __future__ import annotations

import json
import math
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DetectionResult:
    """單一時間窗口的模型與告警結果。"""

    attack_probability: float | None
    model_positive: bool
    candidate: bool
    attack_active: bool
    status: str
    recent_hits: int
    recent_window_size: int
    normal_streak: int
    data_quality_ok: bool
    data_quality_reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LogisticRuntimeModel:
    """使用 JSON 中的 scaler 與 logistic regression 參數推論。"""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.features = list(config["features"])
        self.imputer_median = [float(value) for value in config["imputer_median"]]
        self.scaler_mean = [float(value) for value in config["scaler_mean"]]
        self.scaler_scale = [float(value) for value in config["scaler_scale"]]
        self.coefficient = [float(value) for value in config["coefficient"]]
        self.intercept = float(config["intercept"])

        lengths = {
            len(self.features),
            len(self.imputer_median),
            len(self.scaler_mean),
            len(self.scaler_scale),
            len(self.coefficient),
        }
        if len(lengths) != 1:
            raise ValueError("模型 JSON 的特徵參數長度不一致")
        if any(scale <= 0 for scale in self.scaler_scale):
            raise ValueError("模型 JSON 的 scaler_scale 必須大於 0")

    @classmethod
    def load(cls, path: str | Path) -> "LogisticRuntimeModel":
        model_path = Path(path)
        with model_path.open(encoding="utf-8") as handle:
            return cls(json.load(handle))

    def predict_probability(
        self,
        tcp_packets: int | float,
        tcp_bytes: int | float,
        syn_only_packets: int | float,
        established_connections: int | float = 0,
        active_source_ips: int | float = 0,
    ) -> float:
        """計算與 scikit-learn Pipeline 一致的 label=1 機率。"""
        raw_values = {
            "tcp_packets": float(tcp_packets),
            "tcp_bytes": float(tcp_bytes),
            "syn_only_packets": float(syn_only_packets),
            "active_source_ips": float(active_source_ips),
            "established_connections": float(established_connections),
        }
        if any(not math.isfinite(value) for value in raw_values.values()):
            raise ValueError("模型輸入必須是有限數值")
        if any(value < 0 for value in raw_values.values()):
            raise ValueError("封包數與 bytes 不可為負數")
        if syn_only_packets > tcp_packets:
            raise ValueError("syn_only_packets 不可大於 tcp_packets")

        raw_values["syn_ratio"] = (
            float(syn_only_packets) / tcp_packets if tcp_packets > 0 else 0.0
        )
        raw_values["active_ips_per_established_connection"] = (
            float(active_source_ips) / (float(established_connections) + 1.0)
        )
        unsupported_features = [
            feature for feature in self.features if feature not in raw_values
        ]
        if unsupported_features:
            raise ValueError(
                "模型 JSON 含有 runtime 不支援的特徵："
                + ", ".join(unsupported_features)
            )
        values = [raw_values[feature] for feature in self.features]
        standardized = [
            (value - mean) / scale
            for value, mean, scale in zip(
                values, self.scaler_mean, self.scaler_scale, strict=True
            )
        ]
        logit = self.intercept + sum(
            coefficient * value
            for coefficient, value in zip(
                self.coefficient, standardized, strict=True
            )
        )

        # 穩定版 sigmoid，避免極端輸入造成 exp overflow。
        if logit >= 0:
            exp_negative = math.exp(-logit)
            return 1.0 / (1.0 + exp_negative)
        exp_positive = math.exp(logit)
        return exp_positive / (1.0 + exp_positive)


class SynFloodDetector:
    """將單秒模型分數轉成具持續性與恢復條件的狀態。"""

    def __init__(
        self,
        model: LogisticRuntimeModel,
        *,
        probability_threshold: float | None = None,
        minimum_syn_packets: int | None = None,
        persistence_window_seconds: int | None = None,
        persistence_required_hits: int | None = None,
        clear_after_normal_seconds: int | None = None,
        minimum_valid_window_seconds: float | None = None,
        maximum_valid_window_seconds: float | None = None,
    ):
        config = model.config
        self.model = model
        self.probability_threshold = float(
            config["probability_threshold"]
            if probability_threshold is None
            else probability_threshold
        )
        self.minimum_syn_packets = int(
            config["minimum_syn_packets"]
            if minimum_syn_packets is None
            else minimum_syn_packets
        )
        self.persistence_window_seconds = int(
            config["persistence_window_seconds"]
            if persistence_window_seconds is None
            else persistence_window_seconds
        )
        self.persistence_required_hits = int(
            config["persistence_required_hits"]
            if persistence_required_hits is None
            else persistence_required_hits
        )
        self.clear_after_normal_seconds = int(
            config["clear_after_normal_seconds"]
            if clear_after_normal_seconds is None
            else clear_after_normal_seconds
        )
        self.minimum_valid_window_seconds = float(
            config["minimum_valid_window_seconds"]
            if minimum_valid_window_seconds is None
            else minimum_valid_window_seconds
        )
        self.maximum_valid_window_seconds = float(
            config["maximum_valid_window_seconds"]
            if maximum_valid_window_seconds is None
            else maximum_valid_window_seconds
        )

        if not 0 < self.probability_threshold < 1:
            raise ValueError("機率門檻必須介於 0 與 1")
        if self.minimum_syn_packets < 0:
            raise ValueError("最少 SYN 數不可為負數")
        if not 1 <= self.persistence_required_hits <= self.persistence_window_seconds:
            raise ValueError("持續性規則必須滿足 1 <= hits <= window")
        if self.clear_after_normal_seconds < 1:
            raise ValueError("恢復所需正常秒數至少為 1")
        if not 0 < self.minimum_valid_window_seconds <= self.maximum_valid_window_seconds:
            raise ValueError("無效的時間窗口範圍")

        self.recent_candidates: deque[bool] = deque(
            maxlen=self.persistence_window_seconds
        )
        self.attack_active = False
        self.normal_streak = 0

    @classmethod
    def load(cls, path: str | Path, **overrides: Any) -> "SynFloodDetector":
        return cls(LogisticRuntimeModel.load(path), **overrides)

    def evaluate(
        self,
        *,
        tcp_packets: int,
        tcp_bytes: int,
        syn_only_packets: int,
        established_connections: int = 0,
        active_source_ips: int = 0,
        interval_seconds: float,
        external_quality_ok: bool = True,
        external_quality_reason: str = "ok",
    ) -> DetectionResult:
        """處理一個時間窗口；品質不良時不會改變告警狀態。"""
        duration_ok = (
            self.minimum_valid_window_seconds
            <= interval_seconds
            <= self.maximum_valid_window_seconds
        )
        data_quality_ok = external_quality_ok and duration_ok
        if not external_quality_ok:
            quality_reason = external_quality_reason
        elif not duration_ok:
            quality_reason = (
                f"interval_seconds={interval_seconds:.3f} 不在 "
                f"[{self.minimum_valid_window_seconds:.3f}, "
                f"{self.maximum_valid_window_seconds:.3f}]"
            )
        else:
            quality_reason = "ok"

        if not data_quality_ok:
            return DetectionResult(
                attack_probability=None,
                model_positive=False,
                candidate=False,
                attack_active=self.attack_active,
                status="INSUFFICIENT_DATA",
                recent_hits=sum(self.recent_candidates),
                recent_window_size=len(self.recent_candidates),
                normal_streak=self.normal_streak,
                data_quality_ok=False,
                data_quality_reason=quality_reason,
            )

        probability = self.model.predict_probability(
            tcp_packets=tcp_packets,
            tcp_bytes=tcp_bytes,
            syn_only_packets=syn_only_packets,
            established_connections=established_connections,
            active_source_ips=active_source_ips,
        )
        model_positive = probability >= self.probability_threshold
        candidate = model_positive and syn_only_packets >= self.minimum_syn_packets
        self.recent_candidates.append(candidate)

        if candidate:
            self.normal_streak = 0
        else:
            self.normal_streak += 1

        if not self.attack_active:
            if sum(self.recent_candidates) >= self.persistence_required_hits:
                self.attack_active = True
                self.normal_streak = 0
        elif self.normal_streak >= self.clear_after_normal_seconds:
            self.attack_active = False
            self.recent_candidates.clear()
            self.normal_streak = 0

        if self.attack_active:
            status = "ATTACK"
        elif candidate:
            status = "SUSPECT"
        else:
            status = "NORMAL"

        return DetectionResult(
            attack_probability=probability,
            model_positive=model_positive,
            candidate=candidate,
            attack_active=self.attack_active,
            status=status,
            recent_hits=sum(self.recent_candidates),
            recent_window_size=len(self.recent_candidates),
            normal_streak=self.normal_streak,
            data_quality_ok=True,
            data_quality_reason="ok",
        )
