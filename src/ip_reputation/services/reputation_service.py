"""
Reputation service for IP address risk assessment.
"""

from ip_reputation.api.client import AbuseIPDBClient
from ip_reputation.models import ReputationData
from ip_reputation.constants import RiskLevel, RISK_THRESHOLD_MEDIUM
from ip_reputation.utils.validators import validate_ip_address
from ip_reputation.exceptions import ValidationError, APIError


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
        api_response = self.api_client.check_ip(ip_address, max_age_days)

        # Calculate risk level
        abuse_score = api_response.get("abuseConfidenceScore", 0)
        risk_level = self._calculate_risk_level(abuse_score, confidence_threshold)

        reputation_data = ReputationData(
            ip=api_response.get("ipAddress", ip_address),
            risk_level=risk_level,
            abuse_confidence_score=abuse_score,
            total_reports=api_response.get("totalReports", 0),
            country_code=api_response.get("countryCode", ""),
            isp=api_response.get("isp", ""),
            is_public=api_response.get("isPublic", True),
        )

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

    def process_ip_batch(
        self, ip_addresses: list[str], confidence_threshold: int
    ) -> tuple[dict[str, dict], dict[str, str], dict[str, str]]:
        """
        Process a batch of IP addresses.

        Args:
            ip_addresses: List of IP addresses to check
            confidence_threshold: Threshold for HIGH risk classification

        Returns:
            Tuple of (results_dict, validation_errors_dict, api_errors_dict)
        """
        results = {}
        validation_errors = {}
        api_errors = {}

        for ip in ip_addresses:
            try:
                validated_ip = validate_ip_address(ip)
                reputation_data = self.check_ip(validated_ip, confidence_threshold)
                results[validated_ip] = {
                    "risk_level": reputation_data.risk_level,
                    "abuse_confidence_score": reputation_data.abuse_confidence_score,
                    "total_reports": reputation_data.total_reports,
                    "country_code": reputation_data.country_code,
                    "isp": reputation_data.isp,
                }
            except ValidationError:
                validation_errors[ip] = "Invalid IP address format"
            except APIError as e:
                api_errors[ip] = str(e)
            except Exception as e:
                api_errors[ip] = f"Unexpected error: {str(e)}"

        return results, validation_errors, api_errors

    def _calculate_summary(
        self, total: int, results: dict[str, dict], errors: dict[str, str]
    ) -> dict[str, any]:
        risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for result in results.values():
            risk_level = result.get("risk_level", "LOW")
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        return {
            "total": total,
            "successful": len(results),
            "failed": len(errors),
            "risk_counts": risk_counts,
        }

    def _determine_status_message(self, successful: int, failed: int) -> str:
        from ip_reputation.constants import StatusMessage

        if failed == 0:
            return StatusMessage.SUCCESS.value
        elif successful == 0:
            return StatusMessage.FAILED.value
        else:
            return StatusMessage.PARTIAL_SUCCESS.value

    def build_batch_ip_response(
        self,
        results: dict[str, dict],
        validation_errors: dict[str, str],
        api_errors: dict[str, str],
        total: int,
    ) -> dict[str, any]:
        from ip_reputation.models import (
            BatchSummary,
            BatchAPIObject,
            BatchIPResponse,
            StepStatus,
        )
        from ip_reputation.constants import StatusCode

        all_errors = {**validation_errors, **api_errors}
        summary_dict = self._calculate_summary(total, results, all_errors)
        summary = BatchSummary(**summary_dict)
        status_message = self._determine_status_message(
            summary.successful, len(api_errors)
        )

        # Determine status code
        if len(api_errors) == 0:
            status_code = StatusCode.SUCCESS.value
        elif summary.successful == 0 and len(api_errors) > 0:
            status_code = StatusCode.API_ERROR.value
        else:
            status_code = StatusCode.SUCCESS.value

        response = BatchIPResponse(
            step_status=StepStatus(
                code=status_code,
                message=status_message,
            ),
            api_object=BatchAPIObject(
                summary=summary,
                results=results,
                errors=all_errors,
            ),
        )
        return response.model_dump()
