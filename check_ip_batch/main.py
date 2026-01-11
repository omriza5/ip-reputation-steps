"""
Batch IP reputation checker CLI.
Checks reputation of multiple IP addresses using AbuseIPDB API.
"""

import os
import sys
import json
from typing import Tuple, Dict, Any, List

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


def read_and_validate_inputs() -> Tuple[List[str], str, int]:
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

    return ip_addresses, api_key, confidence_threshold


def process_ip_batch(
    service: ReputationService, ip_addresses: List[str], confidence_threshold: int
) -> Tuple[Dict[str, Dict], Dict[str, str]]:
    """
    Process a batch of IP addresses.

    Args:
        service: ReputationService instance
        ip_addresses: List of IP addresses to check
        confidence_threshold: Threshold for HIGH risk classification

    Returns:
        Tuple of (results_dict, errors_dict)
    """
    results = {}
    validation_errors = {}
    api_errors = {}

    for ip in ip_addresses:
        try:
            # Validate IP format
            validated_ip = validate_ip_address(ip)

            # Check IP reputation
            reputation_data = service.check_ip(validated_ip, confidence_threshold)

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


def calculate_summary(
    total: int, results: Dict[str, Dict], errors: Dict[str, str]
) -> Dict[str, Any]:
    """
    Calculate summary statistics for batch processing.

    Args:
        total: Total number of IPs processed
        results: Dictionary of successful results
        errors: Dictionary of errors

    Returns:
        Summary dictionary with counts
    """
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


def determine_status_message(successful: int, failed: int) -> str:
    """
    Determine status message based on results.

    Args:
        successful: Number of successful checks
        failed: Number of failed checks

    Returns:
        Status message: "success", "partial_success", or "failed"
    """
    if failed == 0:
        return StatusMessage.SUCCESS.value
    elif successful == 0:
        return StatusMessage.FAILED.value
    else:
        return StatusMessage.PARTIAL_SUCCESS.value


def build_response(
    results: Dict[str, Dict], validation_errors: Dict[str, str], api_errors: Dict[str, str], total: int
) -> Dict[str, Any]:
    """
    Build the complete batch response.

    Args:
        results: Dictionary of successful results
        validation_errors: Dict of validation errors
        api_errors: Dict of API errors
        total: Total number of IPs

    Returns:
        Complete response dictionary
    """
    # Merge errors for output and summary
    all_errors = {**validation_errors, **api_errors}
    summary = calculate_summary(total, results, all_errors)
    # Only API errors count for status logic
    api_failed = len(api_errors)
    status_message = determine_status_message(summary["successful"], api_failed)

    # Determine status code
    if api_failed == 0:
        status_code = StatusCode.SUCCESS.value
    elif summary["successful"] == 0 and api_failed > 0:
        status_code = StatusCode.API_ERROR.value
    else:
        status_code = StatusCode.SUCCESS.value

    return {
        "step_status": {"code": status_code, "message": status_message},
        "api_object": {"summary": summary, "results": results, "errors": all_errors},
    }


def main():
    """Main entry point for batch IP checker."""
    try:
        # Read and validate inputs
        ip_addresses, api_key, confidence_threshold = read_and_validate_inputs()

        # Create API client and service
        api_client = AbuseIPDBClient(api_key=api_key)
        service = ReputationService(api_client=api_client)


        # Process all IPs
        results, validation_errors, api_errors = process_ip_batch(service, ip_addresses, confidence_threshold)

        # Build response
        response = build_response(results, validation_errors, api_errors, len(ip_addresses))

        # Print JSON to stdout
        print(json.dumps(response, indent=2))

        # Exit with appropriate code
        sys.exit(response["step_status"]["code"])

    except ValidationError as e:
        # All IPs failed validation
        response = {
            "step_status": {
                "code": StatusCode.VALIDATION_ERROR.value,
                "message": StatusMessage.FAILED.value,
            },
            "api_object": {"error": str(e)},
        }
        print(json.dumps(response, indent=2))
        sys.exit(1)

    except Exception as e:
        # Unexpected error
        response = {
            "step_status": {
                "code": StatusCode.API_ERROR.value,
                "message": StatusMessage.FAILED.value,
            },
            "api_object": {"error": f"Unexpected error: {str(e)}"},
        }
        print(json.dumps(response, indent=2))
        sys.exit(2)


if __name__ == "__main__":
    main()