"""
IP address validation utilities.
"""

import ipaddress
from ip_reputation.exceptions import ValidationError


def validate_ip_address(ip: str) -> str:
    """
    Validate IP address format (IPv4 or IPv6).

    Args:
        ip: IP address string to validate

    Returns:
        The validated IP address string

    Raises:
        ValidationError: If IP address format is invalid
    """
    if not isinstance(ip, str):
        raise ValidationError("IP address must be a string")

    ip = ip.strip()

    if not ip:
        raise ValidationError("IP address cannot be empty or whitespace")

    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise ValidationError(f"Invalid IP address format: {ip}")


def validate_confidence_threshold(
    threshold, min_value: int = 25, max_value: int = 100
) -> int:
    """
    Validate confidence threshold value.

    Args:
        threshold: The threshold value to validate (can be str or int)
        min_value: Minimum allowed value (default: 25)
        max_value: Maximum allowed value (default: 100)

    Returns:
        The validated threshold value

    Raises:
        ValidationError: If threshold is not a valid integer or out of range
    """
    try:
        threshold_int = int(threshold)
    except (ValueError, TypeError):
        raise ValidationError(
            f"CONFIDENCE_THRESHOLD must be an int, got: {threshold}"
        )

    if threshold_int < min_value:
        raise ValidationError(
            f"Confidence threshold must be >= {min_value}, got {threshold_int}"
        )

    if threshold_int > max_value:
        raise ValidationError(
            f"Confidence threshold must be <= {max_value}, got {threshold_int}"
        )

    return threshold_int
