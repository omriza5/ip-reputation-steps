"""
Batch IP reputation checker CLI.
Checks reputation of multiple IP addresses using AbuseIPDB API.
"""

import os
import json
from ip_reputation.api.client import AbuseIPDBClient
from ip_reputation.utils.error_handling import handle_error
from ip_reputation.services.reputation_service import ReputationService
from ip_reputation.utils.validators import (
    validate_confidence_threshold,
)
from ip_reputation.constants import (
    StatusCode,
    DEFAULT_CONFIDENCE_THRESHOLD,
    MIN_CONFIDENCE_THRESHOLD,
    MAX_CONFIDENCE_THRESHOLD,
)
from ip_reputation.exceptions import ValidationError


def read_and_validate_inputs() -> tuple[list[str], str, int]:
    """
    Read and validate environment variables for batch processing.

    Returns:
        Tuple of (ip_addresses_list, api_key, confidence_threshold)

    Raises:
        ValidationError: If inputs are missing or invalid
    """
    # Read environment variables
    ip_addresses_str = os.getenv("IP_ADDRESSES")
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    threshold_str = os.getenv("CONFIDENCE_THRESHOLD", str(DEFAULT_CONFIDENCE_THRESHOLD))

    # Validate required inputs
    if not api_key:
        raise ValidationError("ABUSEIPDB_API_KEY environment variable is required")

    if not ip_addresses_str:
        raise ValidationError("IP_ADDRESSES environment variable is required")

    # Parse comma-separated IPs
    ip_addresses = [ip.strip() for ip in ip_addresses_str.split(",")]

    if not ip_addresses:
        raise ValidationError("IP_ADDRESSES cannot be empty")

    # Validate and convert threshold
    try:
        confidence_threshold = validate_confidence_threshold(
            threshold_str,
            min_value=MIN_CONFIDENCE_THRESHOLD,
            max_value=MAX_CONFIDENCE_THRESHOLD,
        )
        
        return ip_addresses, api_key, confidence_threshold
    except ValidationError as e:
           raise ValidationError(str(e))



def main():
    """Main entry point for batch IP checker."""
    try:
        # Read and validate inputs
        ip_addresses, api_key, confidence_threshold = read_and_validate_inputs()

        # Create API client and service
        api_client = AbuseIPDBClient(api_key=api_key)
        reputation_service = ReputationService(api_client=api_client)

        # Process all IPs
        results, validation_errors, api_errors = reputation_service.process_ip_batch(
            ip_addresses, confidence_threshold
        )

        # Build response
        response = reputation_service.build_batch_ip_response(
            results, validation_errors, api_errors, len(ip_addresses)
        )

        # Print JSON to stdout
        print(json.dumps(response, indent=2))

    except ValidationError as e:
        handle_error(e, StatusCode.VALIDATION_ERROR)

    except Exception as e:
        handle_error(Exception(f"Unexpected error: {str(e)}"), StatusCode.API_ERROR)


if __name__ == "__main__":
    main()
