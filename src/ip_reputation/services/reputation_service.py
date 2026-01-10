"""
Reputation service for IP address risk assessment.
"""

from ip_reputation.api.client import AbuseIPDBClient
from ip_reputation.models import ReputationData
from ip_reputation.constants import RiskLevel, RISK_THRESHOLD_MEDIUM


class ReputationService:
    """Service for checking IP reputation and calculating risk levels."""

    def __init__(self, api_client: AbuseIPDBClient, cache=None):
        """
        Initialize reputation service.

        Args:
            api_client: AbuseIPDB API client instance
            cache: Optional cache backend (for future implementation)
        """
        self.api_client = api_client
        self.cache = cache

    def check_ip(
        self, ip_address: str, confidence_threshold: int, max_age_days: int = 90
    ) -> ReputationData:
        """
        Check IP reputation and calculate risk level.

        Args:
            ip_address: IP address to check
            confidence_threshold: Threshold for HIGH risk classification
            max_age_days: Maximum age of reports to consider

        Returns:
            ReputationData with risk level calculated

        Raises:
            APIError: If API request fails
        """
        # Future: Check cache here
        # if self.cache:
        #     cached = self.cache.get(ip_address)
        #     if cached:
        #         return ReputationData(**cached)

        # Get data from API
        api_response = self.api_client.check_ip(ip_address, max_age_days)

        # Calculate risk level
        abuse_score = api_response.get("abuseConfidenceScore", 0)
        risk_level = self._calculate_risk_level(abuse_score, confidence_threshold)

        # Build ReputationData model
        reputation_data = ReputationData(
            ip=api_response.get("ipAddress", ip_address),
            risk_level=risk_level,
            abuse_confidence_score=abuse_score,
            total_reports=api_response.get("totalReports", 0),
            country_code=api_response.get("countryCode", ""),
            isp=api_response.get("isp", ""),
            is_public=api_response.get("isPublic", True),
        )

        # Future: Store in cache
        # if self.cache:
        #     self.cache.set(ip_address, reputation_data.dict())

        return reputation_data

    def _calculate_risk_level(
        self, abuse_confidence_score: int, confidence_threshold: int
    ) -> str:
        """
        Calculate risk level based on abuse confidence score.

        Args:
            abuse_confidence_score: Score from API (0-100)
            confidence_threshold: Threshold for HIGH risk

        Returns:
            Risk level string: "HIGH", "MEDIUM", or "LOW"
        """
        if abuse_confidence_score >= confidence_threshold:
            return RiskLevel.HIGH.value

        if abuse_confidence_score >= RISK_THRESHOLD_MEDIUM:
            return RiskLevel.MEDIUM.value

        return RiskLevel.LOW.value
