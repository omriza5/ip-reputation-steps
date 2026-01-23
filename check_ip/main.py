"""
Single IP reputation checker CLI.
Checks reputation of a single IP address using AbuseIPDB API.
"""

import os
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
    DEFAULT_CONFIDENCE_THRESHOLD,
    MIN_CONFIDENCE_THRESHOLD,
    MAX_CONFIDENCE_THRESHOLD,
)
from ip_reputation.exceptions import ValidationError, APIError


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
        confidence_threshold = validate_confidence_threshold(
            threshold_str,
            min_value=MIN_CONFIDENCE_THRESHOLD,
            max_value=MAX_CONFIDENCE_THRESHOLD,
        )

        return ip_address, api_key, confidence_threshold
    except ValidationError as e:
        raise ValidationError(str(e))


def main():
    """Main entry point for single IP checker."""
    try:
        # Read and validate inputs
        ip_address, api_key, confidence_threshold = read_and_validate_inputs()

        # Create API client and service
        api_client = AbuseIPDBClient(api_key=api_key)
        reputation_service = ReputationService(api_client=api_client)

        # Check IP reputation
        reputation_data = reputation_service.check_ip(
            ip_address=ip_address, confidence_threshold=confidence_threshold
        )

        # Build and print success response
        response = reputation_service.build_single_ip_response(reputation_data)
        print(json.dumps(response, indent=2))

    except ValidationError as e:
        handle_error(e, StatusCode.VALIDATION_ERROR)

    except APIError as e:
        handle_error(e, StatusCode.API_ERROR)

    except Exception as e:
        error = Exception(f"Unexpected error: {str(e)}")
        handle_error(error, StatusCode.API_ERROR)


if __name__ == "__main__":
    main()
