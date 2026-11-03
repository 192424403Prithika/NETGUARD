from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from backend.app.database.database import Base

class Prediction(Base):
    __tablename__ = "predictions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    prediction_code = Column(String(64), unique=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    duration = Column(Float, default=0.0)
    src_bytes = Column(Float, default=0.0)
    dst_bytes = Column(Float, default=0.0)
    protocol = Column(String(16), default="TCP")
    flag = Column(String(16), default="SF")
    packet_count = Column(Float, default=1.0)
    traffic_features = Column(Text, nullable=True) # JSON string
    
    # ML Engine Scores
    isolation_forest_score = Column(Float, default=0.0)
    reconstruction_error = Column(Float, default=0.0)
    hybrid_score = Column(Float, default=0.0)
    
    # Classification & Evaluation
    classification = Column(String(32), default="NORMAL") # NORMAL or ANOMALY
    attack_type = Column(String(64), default="Normal")    # Normal, DoS, Probe, R2L, U2R, etc.
    severity = Column(String(16), default="NORMAL")       # NORMAL, LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, default=0.0)
    is_simulated = Column(Boolean, default=False)

    alerts = relationship("Alert", back_populates="prediction", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="prediction", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    alert_id = Column(String(64), unique=True, index=True)
    prediction_id = Column(Integer, ForeignKey("predictions.id", ondelete="CASCADE"), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    attack_type = Column(String(64), default="Anomaly")
    severity = Column(String(16), default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    anomaly_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    status = Column(String(16), default="ACTIVE") # ACTIVE, RESOLVED
    detection_message = Column(Text, nullable=True)
    traffic_summary = Column(Text, nullable=True)

    prediction = relationship("Prediction", back_populates="alerts")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_type = Column(String(64), index=True) # PREDICTION, CSV_UPLOAD, ALERT, LIVE_MONITOR, MODEL_TRAIN, SETTING
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    description = Column(Text)
    prediction_id = Column(Integer, ForeignKey("predictions.id", ondelete="CASCADE"), nullable=True)
    details = Column(Text, nullable=True)

    prediction = relationship("Prediction", back_populates="audit_logs")


class ModelMetadata(Base):
    __tablename__ = "model_metadata"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    model_name = Column(String(128), default="NetGuard Isolation Forest + Autoencoder Hybrid")
    model_version = Column(String(32), default="v1.0.0")
    training_date = Column(DateTime, default=datetime.utcnow)
    dataset_name = Column(String(128), default="NSL-KDD / Synthetic Flow")
    number_of_samples = Column(Integer, default=0)
    number_of_features = Column(Integer, default=0)
    threshold = Column(Float, default=0.5)
    weight_iso = Column(Float, default=0.55)
    weight_ae = Column(Float, default=0.45)
    is_active = Column(Boolean, default=True)
    evaluation_metrics = Column(Text, nullable=True) # JSON string of acc, prec, rec, f1, etc.

