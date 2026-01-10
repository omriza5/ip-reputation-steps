"""
Data models for IP reputation checker.
Uses Pydantic for validation and serialization.
"""

from pydantic import BaseModel


class StepStatus(BaseModel):
    """Step execution status."""

    code: int
    message: str


class ReputationData(BaseModel):
    """IP reputation data from AbuseIPDB API."""

    ip: str
    risk_level: str
    abuse_confidence_score: int
    total_reports: int
    country_code: str
    isp: str
    is_public: bool


class SingleIPResponse(BaseModel):
    """Complete response for single IP check."""

    step_status: StepStatus
    api_object: ReputationData


class BatchSummary(BaseModel):
    """Summary statistics for batch IP check."""

    total: int
    successful: int
    failed: int
    risk_counts: dict[str, int]


class BatchAPIObject(BaseModel):
    """API object for batch IP check response."""

    summary: BatchSummary
    results: dict[str, dict]
    errors: dict[str, str]


class BatchIPResponse(BaseModel):
    """Complete response for batch IP check."""

    step_status: StepStatus
    api_object: BatchAPIObject
