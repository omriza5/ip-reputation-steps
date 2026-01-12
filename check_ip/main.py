"""
Single IP reputation checker CLI.
Checks reputation of a single IP address using AbuseIPDB API.
"""

import os
import sys
import json
from ip_reputation.utils.error_handling import handle_error

from ip_reputation.api.client import AbuseIPDBClient
from ip_reputation.services.reputation_service import ReputationService
from ip_reputation.utils.validators import (
    validate_ip_address,
    validate_confidence_threshold,
)
from ip_reputation.constants import (
    StatusCode,
    StatusMessage,
    DEFAULT_CONFIDENCE_THRESHOLD,
    MIN_CONFIDENCE_THRESHOLD,
    MAX_CONFIDENCE_THRESHOLD,
)
from ip_reputation.exceptions import ValidationError, APIError
from ip_reputation.models import (
    ReputationData,
    StepStatus,
    SingleIPResponse,
)


def read_and_validate_inputs() -> tuple[str, str, int]:
    """
    Read and validate environment variables.

    Returns:
        Tuple of (ip_address, api_key, confidence_threshold)

    Raises:
        ValidationError: If inputs are missing or invalid
    """
    # Read environment variables
    ip_address = os.getenv("IP_ADDRESS")
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    threshold_str = os.getenv("CONFIDENCE_THRESHOLD", str(DEFAULT_CONFIDENCE_THRESHOLD))

    # Validate required inputs
    if not api_key:
        raise ValidationError("ABUSEIPDB_API_KEY environment variable is required")

    if not ip_address:
        raise ValidationError("IP_ADDRESS environment variable is required")

    # Validate IP address
    ip_address = validate_ip_address(ip_address)

    # Validate and convert threshold
    try:
        confidence_threshold = int(threshold_str)
    except ValueError:
        raise ValidationError(
            f"CONFIDENCE_THRESHOLD must be a number, got: {threshold_str}"
        )

    confidence_threshold = validate_confidence_threshold(
        confidence_threshold,
        min_value=MIN_CONFIDENCE_THRESHOLD,
        max_value=MAX_CONFIDENCE_THRESHOLD,
    )

    return ip_address, api_key, confidence_threshold


def build_success_response(reputation_data: ReputationData) -> dict:
    """
    Build success JSON response.

    Args:
        reputation_data: ReputationData object from service

    Returns:
        Dictionary containing success response
    """
    response = SingleIPResponse(
        step_status=StepStatus(
            code=StatusCode.SUCCESS.value,
            message=StatusMessage.SUCCESS.value,
        ),
        api_object=reputation_data,
    )
    return response.model_dump()


def main():
    """Main entry point for single IP checker."""
    try:
        # Read and validate inputs
        ip_address, api_key, confidence_threshold = read_and_validate_inputs()

        # Create API client and service
        api_client = AbuseIPDBClient(api_key=api_key)
        service = ReputationService(api_client=api_client)

        # Check IP reputation
        reputation_data = service.check_ip(
            ip_address=ip_address, confidence_threshold=confidence_threshold
        )

        # Build and print success response
        response = build_success_response(reputation_data)
        print(json.dumps(response, indent=2))
        sys.exit(0)

    except ValidationError as e:
        handle_error(e, StatusCode.VALIDATION_ERROR)

    except APIError as e:
        handle_error(e, StatusCode.API_ERROR)

    except Exception as e:
        error = Exception(f"Unexpected error: {str(e)}")
        handle_error(error, StatusCode.API_ERROR)


if __name__ == "__main__":
    main()
