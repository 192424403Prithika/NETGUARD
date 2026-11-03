from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

class ManualPredictRequest(BaseModel):
    duration: float = Field(0.0, description="Duration in seconds")
    src_bytes: float = Field(0.0, description="Source bytes")
    dst_bytes: float = Field(0.0, description="Destination bytes")
    protocol: str = Field("TCP", description="Protocol (TCP, UDP, ICMP)")
    flag: str = Field("SF", description="Connection Flag (SF, S0, REJ, RSTO, SH)")
    packet_count: Optional[float] = Field(1.0, description="Packet count")

class PredictionResponse(BaseModel):
    id: Optional[int] = None
    prediction_code: str
    timestamp: str
    duration: float
    src_bytes: float
    dst_bytes: float
    protocol: str
    flag: str
    packet_count: float
    isolation_forest_score: float
    reconstruction_error: float
    hybrid_score: float
    classification: str
    attack_type: str
    severity: str
    confidence: float
    is_simulated: bool = False

class AlertResponse(BaseModel):
    id: int
    alert_id: str
    prediction_id: Optional[int]
    timestamp: str
    attack_type: str
    severity: str
    anomaly_score: float
    confidence: float
    status: str
    detection_message: Optional[str]
    traffic_summary: Optional[str]
    protocol: Optional[str] = "TCP"
    src_bytes: Optional[float] = 0.0
    dst_bytes: Optional[float] = 0.0
    flag: Optional[str] = "SF"

class AuditLogResponse(BaseModel):
    id: int
    event_type: str
    timestamp: str
    description: str
    prediction_id: Optional[int]
    details: Optional[str]

class DashboardStatsResponse(BaseModel):
    total_inspected: int
    anomalies_found: int
    anomaly_percentage: float
    normal_traffic: int
    attack_types_count: int
    traffic_trend: List[Dict[str, Any]]
    attack_type_distribution: List[Dict[str, Any]]
    avg_anomaly_score_over_time: List[Dict[str, Any]]

class ModelThresholdUpdate(BaseModel):
    threshold: float = Field(..., ge=0.0, le=1.0)
    weight_iso: Optional[float] = Field(0.55, ge=0.0, le=1.0)
    weight_ae: Optional[float] = Field(0.45, ge=0.0, le=1.0)

class ExplainabilityResponse(BaseModel):
    prediction_id: int
    prediction_code: str
    timestamp: str
    classification: str
    attack_type: str
    severity: str
    hybrid_score: float
    isolation_forest_score: float
    reconstruction_error: float
    threshold: float
    weight_iso: float
    weight_ae: float
    feature_contributions: List[Dict[str, Any]]
    plain_english_explanation: str
    traffic_details: Dict[str, Any]

