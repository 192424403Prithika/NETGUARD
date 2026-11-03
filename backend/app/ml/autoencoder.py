import os
import joblib
import numpy as np
from sklearn.neural_network import MLPRegressor
from typing import Tuple, Dict, Any, Optional

class AutoencoderModel:
    """
    Neural Network Autoencoder:
    Input Layer -> Encoder Dense Layer -> Latent Bottleneck -> Decoder Dense Layer -> Output Layer
    """
    def __init__(self, input_dim: int = 6, latent_dim: int = 3, hidden_dim: int = 16):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.hidden_dim = hidden_dim
        
        # Symmetrical Autoencoder Architecture: input -> hidden -> latent -> hidden -> output
        self.model = MLPRegressor(
            hidden_layer_sizes=(hidden_dim, latent_dim, hidden_dim),
            activation='relu',
            solver='adam',
            max_iter=300,
            batch_size=min(64, 256),
            early_stopping=True,
            n_iter_no_change=10,
            random_state=42
        )
        self.is_trained = False
        self.min_error = 0.0
        self.max_error = 1.0

    def fit(self, X: np.ndarray):
        # Autoencoder is trained to reconstruct its input (X -> X)
        self.model.fit(X, X)
        self.is_trained = True
        
        # Calibrate baseline reconstruction error bounds
        recon = self.model.predict(X)
        errors = np.mean(np.square(X - recon), axis=1)
        self.min_error = float(np.percentile(errors, 5))
        self.max_error = float(np.percentile(errors, 95))
        if self.max_error <= self.min_error:
            self.max_error = self.min_error + 1.0
        return self

    def reconstruct(self, X: np.ndarray) -> np.ndarray:
        if not self.is_trained:
            return X.copy()
        return self.model.predict(X)

    def get_reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """
        Calculates Mean Squared Error (MSE) per sample:
        MSE = (1/d) * sum((X - X_pred)^2)
        """
        if not self.is_trained:
            # Baseline synthetic error
            return np.zeros(X.shape[0])
        recon = self.reconstruct(X)
        mse = np.mean(np.square(X - recon), axis=1)
        return mse

    def get_feature_errors(self, X: np.ndarray) -> np.ndarray:
        """
        Returns feature-wise squared error: (x_i - x_pred_i)^2
        Used directly in Explainability.
        """
        if not self.is_trained:
            return np.zeros_like(X)
        recon = self.reconstruct(X)
        return np.square(X - recon)

    def normalize_error(self, mse_values: np.ndarray) -> np.ndarray:
        """
        Normalizes reconstruction error to [0, 1] range.
        """
        denom = max(self.max_error - self.min_error, 1e-6)
        normalized = (mse_values - self.min_error) / denom
        return np.clip(normalized, 0.0, 1.0)

    def save(self, filepath: str):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            "model": self.model,
            "is_trained": self.is_trained,
            "min_error": self.min_error,
            "max_error": self.max_error,
            "input_dim": self.input_dim,
            "latent_dim": self.latent_dim,
            "hidden_dim": self.hidden_dim
        }, filepath)

    def load(self, filepath: str) -> bool:
        if os.path.exists(filepath):
            data = joblib.load(filepath)
            self.model = data["model"]
            self.is_trained = data["is_trained"]
            self.min_error = data.get("min_error", 0.0)
            self.max_error = data.get("max_error", 1.0)
            self.input_dim = data.get("input_dim", 6)
            self.latent_dim = data.get("latent_dim", 3)
            self.hidden_dim = data.get("hidden_dim", 16)
            return True
        return False

