import os
import random
import string
from datetime import datetime, timedelta
import numpy as np
import pandas as pd
from sqlalchemy.orm import Session

from backend.app.ml.hybrid_model import HybridAnomalyDetector
from backend.app.models.db_models import Prediction, Alert, AuditLog, ModelMetadata

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_DIR = os.path.join(BASE_DIR, "saved_models", "active_hybrid_model")
DATASET_DIR = os.path.join(os.path.dirname(BASE_DIR), "datasets")

class MLService:
    _instance = None

    def __init__(self):
        self.detector = HybridAnomalyDetector(weight_iso=0.55, weight_ae=0.45, threshold=0.5)
        self.is_initialized = False
        self._initialize_or_train()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = MLService()
        return cls._instance

    def _initialize_or_train(self):
        if self.detector.load(MODEL_DIR):
            self.is_initialized = True
            print("Loaded existing NetGuard Hybrid Anomaly Detection Model from disk.")
            return

        print("Training initial NetGuard Hybrid Anomaly Detection Model...")
        os.makedirs(DATASET_DIR, exist_ok=True)
        synthetic_path = os.path.join(DATASET_DIR, "nsl_kdd_sample.csv")
        
        # Generate representative network traffic training dataset if not present
        if not os.path.exists(synthetic_path):
            df = self.generate_synthetic_network_dataset(num_samples=1200)
            df.to_csv(synthetic_path, index=False)
        else:
            df = pd.read_csv(synthetic_path)

        self.detector.fit(df, label_col="label")
        self.detector.save(MODEL_DIR)
        self.is_initialized = True
        print("NetGuard Hybrid Model trained and saved successfully.")

    def generate_synthetic_network_dataset(self, num_samples: int = 1200) -> pd.DataFrame:
        """
        Generates realistic network security traffic dataset modeling NSL-KDD distributions
        (Normal, DoS, Probe, R2L, U2R).
        """
        np.random.seed(42)
        random.seed(42)
        records = []

        for _ in range(num_samples):
            rand = random.random()
            if rand < 0.70:
                # Normal Traffic: typical web browsing, DNS, SSH, API calls
                proto = random.choices(["TCP", "UDP", "ICMP"], weights=[0.8, 0.18, 0.02])[0]
                flag = random.choices(["SF", "OTH"], weights=[0.97, 0.03])[0]
                dur = round(max(0.01, random.expovariate(0.5)), 2)
                src_b = int(np.random.lognormal(mean=7.0, sigma=1.2)) # ~500 - 8000 bytes
                dst_b = int(np.random.lognormal(mean=8.2, sigma=1.5)) # ~1000 - 25000 bytes
                pkts = random.randint(2, 45)
                label = "Normal"
            elif rand < 0.85:
                # DoS Attack: huge volume, short duration, SYN flood (S0 flag) or ICMP flood
                proto = random.choices(["TCP", "ICMP", "UDP"], weights=[0.75, 0.20, 0.05])[0]
                flag = random.choices(["S0", "REJ", "SF"], weights=[0.8, 0.15, 0.05])[0]
                dur = round(random.uniform(0.0, 0.4), 3)
                src_b = random.randint(30000, 180000)
                dst_b = random.randint(0, 120)
                pkts = random.randint(80, 500)
                label = "DoS"
            elif rand < 0.94:
                # Probe Attack: port sweeps, host scans, zero-payload SYN scans
                proto = random.choices(["TCP", "UDP", "ICMP"], weights=[0.7, 0.25, 0.05])[0]
                flag = random.choices(["S0", "REJ", "RSTO"], weights=[0.6, 0.3, 0.1])[0]
                dur = round(random.uniform(0.0, 2.5), 2)
                src_b = random.randint(0, 350)
                dst_b = random.randint(0, 60)
                pkts = random.randint(1, 4)
                label = "Probe"
            else:
                # R2L Attack: unauthorized remote-to-local access attempts, brute-force, high payloads
                proto = "TCP"
                flag = random.choices(["REJ", "RSTO", "SF"], weights=[0.7, 0.2, 0.1])[0]
                dur = round(random.uniform(0.2, 8.0), 2)
                src_b = random.randint(18000, 45000)
                dst_b = random.randint(12000, 35000)
                pkts = random.randint(15, 60)
                label = "R2L"

            records.append({
                "duration": dur,
                "src_bytes": src_b,
                "dst_bytes": dst_b,
                "protocol": proto,
                "flag": flag,
                "packet_count": pkts,
                "label": label
            })

        return pd.DataFrame(records)

    def predict_sample(self, duration: float, src_bytes: float, dst_bytes: float,
                       protocol: str, flag: str, packet_count: float = 1.0) -> dict:
        return self.detector.predict_single(duration, src_bytes, dst_bytes, protocol, flag, packet_count)

    def predict_batch_df(self, df: pd.DataFrame) -> list:
        return self.detector.predict_batch(df)

    def train_on_dataframe(self, df: pd.DataFrame, label_col: str = None) -> dict:
        self.detector.fit(df, label_col=label_col)
        self.detector.save(MODEL_DIR)
        return self.detector.metrics

    def set_threshold_and_weights(self, threshold: float, weight_iso: float = 0.55, weight_ae: float = 0.45):
        self.detector.threshold = threshold
        self.detector.weight_iso = weight_iso
        self.detector.weight_ae = weight_ae
        self.detector.save(MODEL_DIR)
