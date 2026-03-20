from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Dict, Iterable, List, Union

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
except ImportError:  # pragma: no cover - fallback keeps the firewall runnable
    np = None
    IsolationForest = None


@dataclass
class TrafficFeatures:
    requests_per_ip: float
    request_frequency: float
    packet_size: float
    port_number: float

    def to_vector(self) -> List[float]:
        return [
            float(self.requests_per_ip),
            float(self.request_frequency),
            float(self.packet_size),
            float(self.port_number),
        ]


class AnomalyDetector:
    """Small Isolation Forest wrapper used by the firewall."""

    def __init__(self) -> None:
        self.model = None
        if IsolationForest is not None:
            self.model = IsolationForest(
                n_estimators=60,
                contamination=0.08,
                random_state=42,
                n_jobs=1,
            )
            self._train()

    def _simulate_normal_traffic(self, samples: int = 300) -> np.ndarray:
        # We train on lightweight synthetic traffic so the model is ready
        # immediately and does not require a separate dataset file.
        normal_rows = []
        common_ports = [80, 443, 8080]
        for _ in range(samples):
            normal_rows.append(
                [
                    random.randint(1, 40),
                    round(random.uniform(0.05, 2.5), 2),
                    random.randint(200, 1800),
                    random.choice(common_ports),
                ]
            )
        return np.array(normal_rows, dtype=float)

    def _train(self) -> None:
        # Isolation Forest works well for quick anomaly checks on mostly
        # normal traffic because it does not need labeled attack samples.
        training_data = self._simulate_normal_traffic()
        self.model.fit(training_data)

    def _coerce_features(self, features: Union[Dict, TrafficFeatures, Iterable[float]]) -> List[float]:
        if isinstance(features, TrafficFeatures):
            return features.to_vector()
        if isinstance(features, dict):
            return TrafficFeatures(
                requests_per_ip=features.get("requests_per_ip", 0),
                request_frequency=features.get("request_frequency", 0),
                packet_size=features.get("packet_size", 0),
                port_number=features.get("port_number", 0),
            ).to_vector()
        return [float(value) for value in features]

    def score(self, features: Union[Dict, TrafficFeatures, Iterable[float]]) -> float:
        if self.model is None or np is None:
            return self._heuristic_score(self._coerce_features(features))
        vector = np.array([self._coerce_features(features)], dtype=float)
        return float(self.model.decision_function(vector)[0])

    def detect_anomaly(self, features: Union[Dict, TrafficFeatures, Iterable[float]]) -> str:
        if self.model is None or np is None:
            return "ANOMALY" if self._heuristic_score(self._coerce_features(features)) < 0 else "NORMAL"
        vector = np.array([self._coerce_features(features)], dtype=float)
        prediction = int(self.model.predict(vector)[0])
        return "ANOMALY" if prediction == -1 else "NORMAL"

    def _heuristic_score(self, features: List[float]) -> float:
        requests_per_ip, request_frequency, packet_size, port_number = features
        score = 1.0
        if requests_per_ip > 70:
            score -= 0.7
        if request_frequency > 3:
            score -= 0.7
        if packet_size > 3000:
            score -= 0.2
        if port_number not in {80, 443, 8080}:
            score -= 0.2
        return score
