import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Optional

class IsolationForestModel:
    def __init__(self, n_estimators: int = 150, contamination: float = 0.1, random_state: int = 42):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1
        )
        self.is_trained = False
        self.min_score = -0.5
        self.max_score = 0.5

    def fit(self, X: np.ndarray):
        self.model.fit(X)
        self.is_trained = True
        
        # Scikit-learn score_samples: more negative = more anomalous
        # decision_function: negative = anomaly, positive = normal
        scores = self.model.decision_function(X)
        self.min_score = float(np.percentile(scores, 5))
        self.max_score = float(np.percentile(scores, 95))
        if self.max_score <= self.min_score:
            self.max_score = self.min_score + 1.0
        return self

    def get_raw_score(self, X: np.ndarray) -> np.ndarray:
        """
        Returns decision_function values (positive = normal, negative = anomaly).
        """
        if not self.is_trained:
            return np.zeros(X.shape[0])
        return self.model.decision_function(X)

    def get_anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """
        Converts decision function into [0, 1] anomaly score where 1 = highest anomaly.
        """
        if not self.is_trained:
            return np.full(X.shape[0], 0.2)
        
        raw = self.model.decision_function(X)
        # Invert: low raw score => high anomaly score
        denom = max(self.max_score - self.min_score, 1e-6)
        normalized = (self.max_score - raw) / denom
        return np.clip(normalized, 0.0, 1.0)

    def save(self, filepath: str):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            "model": self.model,
            "is_trained": self.is_trained,
            "min_score": self.min_score,
            "max_score": self.max_score,
            "n_estimators": self.n_estimators,
            "contamination": self.contamination
        }, filepath)

    def load(self, filepath: str) -> bool:
        if os.path.exists(filepath):
            data = joblib.load(filepath)
            self.model = data["model"]
            self.is_trained = data["is_trained"]
            self.min_score = data.get("min_score", -0.5)
            self.max_score = data.get("max_score", 0.5)
            self.n_estimators = data.get("n_estimators", 150)
            self.contamination = data.get("contamination", 0.1)
            return True
        return False

