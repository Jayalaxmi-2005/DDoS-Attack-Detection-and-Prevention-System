"""
anomaly_detector.py — Anomaly-Based Adaptive Detection
=======================================================
Uses scikit-learn's Isolation Forest to detect novel or unknown traffic
patterns that don't match learned 'normal' behaviour.

Why Isolation Forest?
---------------------
- Unsupervised: no attack labels needed during training.
- Trains only on NORMAL traffic samples, so deviations (even new attack types)
  score as anomalies.
- Fast at inference — suitable for near real-time packet scoring.

Limitations (clearly stated for the project report)
----------------------------------------------------
- Trained on synthetic normal traffic. The decision boundary reflects the
  synthetic feature distribution, not real network traffic.
- Anomaly score threshold is set heuristically; in a real deployment it
  would be tuned on labelled validation data.
"""

import os
import pickle
import numpy as np

from sklearn.ensemble import IsolationForest

from simulator import FEATURE_NAMES, generate_batch

MODEL_DIR  = os.path.join(os.path.dirname(__file__), "models")
ISO_PATH   = os.path.join(MODEL_DIR, "isolation_forest.pkl")


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train_anomaly(n_normal=4000, contamination=0.05, save=True):
    """
    Train Isolation Forest on synthetic NORMAL traffic only.

    Parameters
    ----------
    n_normal      : int   — number of normal samples to train on
    contamination : float — expected fraction of outliers in training data
                            (a small amount of noise is realistic)
    save          : bool  — persist model to disk

    Returns
    -------
    IsolationForest instance
    """
    print(f"[Anomaly] Generating {n_normal} normal traffic samples …")
    normal_packets = generate_batch(n=n_normal, traffic_type="normal")
    X = np.array([[p[f] for f in FEATURE_NAMES] for p in normal_packets])

    print("[Anomaly] Training Isolation Forest …")
    iso = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X)

    if save:
        os.makedirs(MODEL_DIR, exist_ok=True)
        with open(ISO_PATH, "wb") as f:
            pickle.dump(iso, f)
        print(f"[Anomaly] Model saved to {ISO_PATH}")

    return iso


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------
class AnomalyDetector:
    """
    Wraps Isolation Forest for real-time anomaly scoring.

    score() returns a normalised anomaly score in [0, 1]:
      0 = very normal
      1 = highly anomalous
    """

    # Raw IF scores are negative; map to 0‥1 for the dashboard
    # IF decision_function returns values roughly in [-0.5, 0.5]
    _SCORE_OFFSET = 0.5   # shift so 0 → normal baseline
    _SCORE_SCALE  = 1.0   # scale; clipped to [0,1]

    # Packets with normalised score above this are flagged as anomalies
    ANOMALY_THRESHOLD = 0.55

    def __init__(self):
        self.model   = None
        self._loaded = False

    def load(self):
        """Load model from disk. Train first if not found."""
        if not os.path.exists(ISO_PATH):
            print("[Anomaly] No saved model found — training now …")
            self.model = train_anomaly()
        else:
            with open(ISO_PATH, "rb") as f:
                self.model = pickle.load(f)
            print("[Anomaly] Loaded saved model.")
        self._loaded = True

    def score(self, packet: dict) -> dict:
        """
        Compute anomaly score for one packet.

        Returns
        -------
        dict with:
          anomaly_score : float 0‥1  (higher = more anomalous)
          is_anomaly    : bool
          decision_raw  : raw IF decision_function value (for debugging)
        """
        if not self._loaded:
            raise RuntimeError("Call load() before score().")

        features = np.array([[packet[f] for f in FEATURE_NAMES]])

        # decision_function: positive → inlier, negative → outlier
        raw   = float(self.model.decision_function(features)[0])
        # Normalise: flip sign (anomaly should be HIGH), shift, clip
        norm  = float(np.clip(-raw + self._SCORE_OFFSET, 0.0, 1.0))

        return {
            "anomaly_score": round(norm, 4),
            "is_anomaly":    norm >= self.ANOMALY_THRESHOLD,
            "decision_raw":  round(raw, 4),
        }

    def get_model_stats(self) -> dict:
        return {
            "type":           "Isolation Forest",
            "n_estimators":   getattr(self.model, "n_estimators", "?"),
            "contamination":  getattr(self.model, "contamination", "?"),
            "threshold":      self.ANOMALY_THRESHOLD,
            "training_data":  "Synthetic normal traffic only",
            "note": (
                "Detects novel/unknown anomalies without requiring attack labels. "
                "Trained on synthetic data; threshold is heuristic."
            ),
        }
