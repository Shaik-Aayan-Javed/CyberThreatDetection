"""The machine-learning component: unsupervised anomaly scoring.

Why it exists, plainly: the five rule detectors above encode threats we already
know how to describe. This model encodes what *normal* looks like on this link,
so traffic that is merely strange still surfaces. It complements the evidence;
it never overrides it.

Model      IsolationForest (sklearn), 200 trees.
Trained on Benign windows only -- see docs/MODEL.md. Training never sees an
           attack, which matters for a passive monitor: you can collect quiet
           traffic from a production link, but you cannot collect labelled
           attacks from one.
Features   The 10-dimension per-host vector in features/extract.host_vector.
Output     A calibrated 0..1 anomaly score. High = unlike anything in training.

The score does two jobs:
  1. it is attached to every rule-based alert as corroboration, and
  2. above a high threshold it raises a low-severity ANOMALOUS_FLOW on its own.

Deliberately NOT done: no deep network, no packet-bytes-as-tensor model, no
claim that the model understands protocols. It is a density estimate over ten
hand-engineered features, which is what the evidence can actually support.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import numpy as np

from alerts.schema import ANOMALOUS_FLOW, Alert, Evidence
from detectors.base import Detector
from features.baseline import BaselineTracker
from features.extract import VECTOR_FEATURE_NAMES, HostFeatures, WindowFeatures, host_vector

DEFAULT_MODEL_PATH = os.path.join("models", "anomaly.joblib")

# Standalone alerts only above this calibrated score. Set high because an
# unsupervised model with no attack labels should be quiet by default -- a noisy
# anomaly channel is worse than none.
ALERT_THRESHOLD = 0.92
# Hosts quieter than this are not scored; single-packet hosts are not evidence.
MIN_PACKETS = 20


# The calibrated score assigned to the single most unusual window in the
# training set. Anything scoring above this is stranger than anything the model
# saw while learning normal, which is what ALERT_THRESHOLD sits just above.
BENIGN_EXTREME_ANCHOR = 0.90


@dataclass
class Calibration:
    """Maps raw IsolationForest decision values onto a 0..1 anomaly score.

    Anchored on the training distribution: the median benign window maps to 0.0,
    and the *most extreme* benign window maps to 0.90. So a score above 0.90
    means "more unusual than anything in the benign training data" -- a claim
    that is checkable, unlike a bare model output.

    An earlier version anchored 1.0 at the benign 1st percentile, which
    guaranteed by construction that ~1% of benign windows would score at the top
    and alert. Measured against normal.pcap that produced 5 false positives. The
    anchor moved to the benign minimum specifically to make the anomaly channel
    silent on traffic that resembles its training set.
    """

    p50: float
    extreme: float  # most anomalous raw score seen in benign training data

    def to_score(self, raw: float) -> float:
        spread = self.p50 - self.extreme
        if spread <= 1e-9:
            return 0.0
        scaled = (self.p50 - raw) / spread * BENIGN_EXTREME_ANCHOR
        return float(np.clip(scaled, 0.0, 1.0))


class AnomalyModel:
    """Thin wrapper so training, persistence, and scoring live in one place."""

    def __init__(self, model=None, scaler=None, calib: Calibration | None = None):
        self.model = model
        self.scaler = scaler
        self.calib = calib

    @property
    def ready(self) -> bool:
        return self.model is not None and self.calib is not None

    def fit(self, vectors: np.ndarray, n_estimators: int = 200, seed: int = 42) -> dict:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        self.scaler = StandardScaler().fit(vectors)
        scaled = self.scaler.transform(vectors)

        self.model = IsolationForest(
            n_estimators=n_estimators,
            # Benign-only training set, so we tell the forest to expect almost
            # no outliers rather than the sklearn default of 'auto'.
            contamination=0.01,
            max_samples="auto",
            random_state=seed,
            n_jobs=-1,
        ).fit(scaled)

        raw = self.model.decision_function(scaled)
        self.calib = Calibration(p50=float(np.median(raw)), extreme=float(raw.min()))
        benign = self.score_many(vectors)
        return {
            "samples": int(vectors.shape[0]),
            "features": int(vectors.shape[1]),
            "n_estimators": n_estimators,
            "calibration_median_raw": self.calib.p50,
            "calibration_extreme_raw": self.calib.extreme,
            # Must stay below ALERT_THRESHOLD, or the model alerts on its own
            # training data. Asserted by tools/selftest.py.
            "benign_max_score": round(float(benign.max()), 4),
            "alert_threshold": ALERT_THRESHOLD,
        }

    def score(self, vector: list[float]) -> float:
        if not self.ready:
            return 0.0
        scaled = self.scaler.transform(np.asarray(vector, dtype=float).reshape(1, -1))
        raw = float(self.model.decision_function(scaled)[0])
        return self.calib.to_score(raw)

    def score_many(self, vectors: np.ndarray) -> np.ndarray:
        if not self.ready:
            return np.zeros(len(vectors))
        raw = self.model.decision_function(self.scaler.transform(vectors))
        spread = self.calib.p50 - self.calib.extreme
        if spread <= 1e-9:
            return np.zeros_like(raw)
        return np.clip((self.calib.p50 - raw) / spread * BENIGN_EXTREME_ANCHOR, 0.0, 1.0)

    def save(self, path: str) -> None:
        import joblib

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        joblib.dump(
            {"model": self.model, "scaler": self.scaler,
             "p50": self.calib.p50, "extreme": self.calib.extreme,
             "features": VECTOR_FEATURE_NAMES},
            path,
        )

    @classmethod
    def load(cls, path: str) -> "AnomalyModel":
        import joblib

        blob = joblib.load(path)
        return cls(
            model=blob["model"],
            scaler=blob["scaler"],
            calib=Calibration(p50=blob["p50"], extreme=blob["extreme"]),
        )


class AnomalyDetector(Detector):
    """Scores every host in every window; alerts only on strong outliers."""

    name = "anomaly.iforest.v1"
    threat_class = ANOMALOUS_FLOW
    cooldown_s = 90.0

    def __init__(self, model_path: str = DEFAULT_MODEL_PATH, alert: bool = True):
        super().__init__()
        self.alert = alert
        self.model = AnomalyModel()
        # Last score per source, so the engine can attach corroboration to rule
        # alerts raised in the same window.
        self.last_scores: dict[str, float] = {}
        if model_path and os.path.exists(model_path):
            try:
                self.model = AnomalyModel.load(model_path)
            except Exception as exc:  # pragma: no cover
                print(f"[anomaly] could not load {model_path}: {exc}")

    @property
    def is_trained(self) -> bool:
        return self.model.ready

    def on_window(self, wf: WindowFeatures, baselines: BaselineTracker) -> list[Alert]:
        self.last_scores.clear()
        if not self.model.ready:
            return []

        # Score every host in the window with ONE sklearn call. Scoring hosts
        # individually costs a scaler.transform plus a full forest traversal per
        # host; batching them cut end-to-end pipeline throughput loss from ~70%
        # to a few percent, measured with bench/throughput.py.
        hosts = [(src, hf) for src, hf in wf.by_src.items() if hf.packets >= MIN_PACKETS]
        if not hosts:
            return []

        vectors = np.asarray([host_vector(hf, wf.duration) for _, hf in hosts], dtype=float)
        scores = self.model.score_many(vectors)

        alerts: list[Alert] = []
        for (src, hf), vector, score in zip(hosts, vectors, scores):
            score = float(score)
            self.last_scores[src] = score

            if not self.alert or score < ALERT_THRESHOLD:
                continue
            if not self.ready(src, wf.window.end):
                continue
            self.mark(src, wf.window.end)

            alerts.append(self._build(wf, hf, vector, score))
        return alerts

    def _build(self, wf: WindowFeatures, hf: HostFeatures, vector, score) -> Alert:
        # Report the three features furthest from the training mean -- that is
        # the closest an IsolationForest gets to an explanation, and it is
        # honest about being a ranking rather than a causal claim.
        scaled = self.model.scaler.transform(np.asarray(vector).reshape(1, -1))[0]
        order = np.argsort(-np.abs(scaled))[:3]

        evidence = [
            Evidence("anomaly_score", score, ALERT_THRESHOLD, "",
                     "IsolationForest trained on benign traffic only"),
        ]
        for i in order:
            evidence.append(
                Evidence(
                    VECTOR_FEATURE_NAMES[i],
                    float(vector[i]),
                    float(self.model.scaler.mean_[i]),
                    "",
                    f"{abs(scaled[i]):.1f} standard deviations from the benign mean",
                )
            )
        evidence.append(Evidence("packets_in_window", hf.packets, None, "packets"))

        return Alert.build(
            threat_class=self.threat_class,
            detector=self.name,
            confidence=score,
            flow_id=f"{hf.src}->* (behavioural)",
            src=hf.src,
            dst=f"{len(hf.dst_hosts)} hosts",
            window_start=wf.window.start,
            window_end=wf.window.end,
            evidence=evidence,
            anomaly_score=score,
        )
