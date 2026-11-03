import os
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from typing import Dict, List, Tuple, Any, Optional

STANDARD_FEATURES = ["duration", "src_bytes", "dst_bytes", "packet_count"]
CATEGORICAL_FEATURES = ["protocol", "flag"]

PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2}
FLAG_MAP = {"SF": 0, "S0": 1, "REJ": 2, "RSTO": 3, "SH": 4, "OTH": 5}

COLUMN_SYNONYMS = {
    "duration": ["duration", "flow_duration", "dur", "flow duration"],
    "src_bytes": ["src_bytes", "source_bytes", "sbytes", "totlen_fwd_pkts", "src_ip_bytes", "src bytes"],
    "dst_bytes": ["dst_bytes", "destination_bytes", "dbytes", "totlen_bwd_pkts", "dst_ip_bytes", "dst bytes"],
    "packet_count": ["packet_count", "count", "spkts", "dpkts", "total_packets", "packets"],
    "protocol": ["protocol", "protocol_type", "proto"],
    "flag": ["flag", "conn_state", "state"],
    "label": ["label", "class", "attack", "target", "attack_cat", "normal"]
}

class NetworkDataPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.feature_names: List[str] = []
        self.is_fitted = False

    def standardize_column_names(self, df: pd.DataFrame) -> pd.DataFrame:
        clean_df = df.copy()
        clean_df.columns = [str(c).strip().lower().replace(" ", "_") for c in clean_df.columns]
        
        rename_dict = {}
        for target, synonyms in COLUMN_SYNONYMS.items():
            for syn in synonyms:
                clean_syn = syn.lower().replace(" ", "_")
                if clean_syn in clean_df.columns and target not in rename_dict.values():
                    rename_dict[clean_syn] = target
                    break
        clean_df = clean_df.rename(columns=rename_dict)
        return clean_df

    def fit(self, df: pd.DataFrame):
        df = self.standardize_column_names(df)
        
        # Ensure numerical columns exist
        for col in STANDARD_FEATURES:
            if col not in df.columns:
                df[col] = 0.0
            else:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)

        # Categorical mappings
        proto_encoded = df.get("protocol", "TCP").astype(str).str.upper().map(PROTOCOL_MAP).fillna(0)
        flag_encoded = df.get("flag", "SF").astype(str).str.upper().map(FLAG_MAP).fillna(0)

        numerical_data = df[STANDARD_FEATURES].values
        features = np.column_stack([numerical_data, proto_encoded.values, flag_encoded.values])
        
        self.scaler.fit(features)
        self.feature_names = STANDARD_FEATURES + ["protocol_encoded", "flag_encoded"]
        self.is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        df = self.standardize_column_names(df)
        
        for col in STANDARD_FEATURES:
            if col not in df.columns:
                df[col] = 0.0
            else:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)

        proto_encoded = df.get("protocol", "TCP").astype(str).str.upper().map(PROTOCOL_MAP).fillna(0)
        flag_encoded = df.get("flag", "SF").astype(str).str.upper().map(FLAG_MAP).fillna(0)

        numerical_data = df[STANDARD_FEATURES].values
        features = np.column_stack([numerical_data, proto_encoded.values, flag_encoded.values])
        
        if not self.is_fitted:
            self.scaler.fit(features)
            self.feature_names = STANDARD_FEATURES + ["protocol_encoded", "flag_encoded"]
            self.is_fitted = True

        return self.scaler.transform(features)

    def transform_single(self, duration: float, src_bytes: float, dst_bytes: float,
                         protocol: str, flag: str, packet_count: float = 1.0) -> np.ndarray:
        proto_val = PROTOCOL_MAP.get(protocol.upper(), 0)
        flag_val = FLAG_MAP.get(flag.upper(), 0)
        sample = np.array([[duration, src_bytes, dst_bytes, packet_count, proto_val, flag_val]])
        
        if not self.is_fitted:
            self.scaler.fit(sample)
            self.feature_names = STANDARD_FEATURES + ["protocol_encoded", "flag_encoded"]
            self.is_fitted = True

        return self.scaler.transform(sample)

    def save(self, filepath: str):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({"scaler": self.scaler, "feature_names": self.feature_names, "is_fitted": self.is_fitted}, filepath)

    def load(self, filepath: str):
        if os.path.exists(filepath):
            data = joblib.load(filepath)
            self.scaler = data["scaler"]
            self.feature_names = data["feature_names"]
            self.is_fitted = data["is_fitted"]
            return True
        return False

