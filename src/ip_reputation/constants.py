"""
Constants for IP reputation checker.
Defines status codes, risk levels, thresholds, and API configuration.
"""

from enum import Enum


class StatusCode(Enum):
    """Step execution status codes."""

    SUCCESS = 0
    VALIDATION_ERROR = 1
    API_ERROR = 2


class StatusMessage(Enum):
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"


class RiskLevel(Enum):
    """IP address risk classification levels."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Minimum score for MEDIUM risk
RISK_THRESHOLD_MEDIUM = 25

# Threshold Validation
MIN_CONFIDENCE_THRESHOLD = RISK_THRESHOLD_MEDIUM
MAX_CONFIDENCE_THRESHOLD = 100

# API Configuration
ABUSEIPDB_API_BASE_URL = "https://api.abuseipdb.com/api/v2"
ABUSEIPDB_CHECK_ENDPOINT = "/check"
API_TIMEOUT_SECONDS = 30

# Default Values
DEFAULT_CONFIDENCE_THRESHOLD = 70
DEFAULT_MAX_AGE_DAYS = 90
