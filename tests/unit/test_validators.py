"""
Unit tests for validation functions.
"""

import pytest
from ip_reputation.utils.validators import (
    validate_ip_address,
    validate_confidence_threshold,
)
from ip_reputation.exceptions import ValidationError


class TestValidateIPAddress:
    """Tests for validate_ip_address function."""

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        assert validate_ip_address("192.168.1.1") == "192.168.1.1"
        assert validate_ip_address("8.8.8.8") == "8.8.8.8"
        assert validate_ip_address("118.25.6.39") == "118.25.6.39"

    def test_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        assert validate_ip_address("2001:0db8::1") == "2001:0db8::1"
        assert validate_ip_address("::1") == "::1"

    def test_ip_with_whitespace(self):
        """Test IP addresses with leading/trailing whitespace."""
        assert validate_ip_address("  8.8.8.8  ") == "8.8.8.8"
        assert validate_ip_address("\t192.168.1.1\n") == "192.168.1.1"

    def test_empty_string(self):
        """Test empty string raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_ip_address("")

    def test_whitespace_only(self):
        """Test whitespace-only string raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_ip_address("   ")

    def test_invalid_format(self):
        """Test invalid IP format raises ValidationError."""
        with pytest.raises(ValidationError, match="Invalid IP address format"):
            validate_ip_address("invalid-ip")

        with pytest.raises(ValidationError, match="Invalid IP address format"):
            validate_ip_address("999.999.999.999")

        with pytest.raises(ValidationError, match="Invalid IP address format"):
            validate_ip_address("192.168.1")

    def test_non_string_input(self):
        """Test non-string input raises ValidationError."""
        with pytest.raises(ValidationError, match="must be a string"):
            validate_ip_address(123)

        with pytest.raises(ValidationError, match="must be a string"):
            validate_ip_address(None)


class TestValidateConfidenceThreshold:
    """Tests for validate_confidence_threshold function."""

    def test_valid_threshold(self):
        """Test valid threshold values."""
        assert validate_confidence_threshold(70) == 70
        assert validate_confidence_threshold(50) == 50
        assert validate_confidence_threshold(90) == 90

    def test_minimum_threshold(self):
        """Test minimum allowed threshold (25)."""
        assert validate_confidence_threshold(25) == 25

    def test_maximum_threshold(self):
        """Test maximum allowed threshold (100)."""
        assert validate_confidence_threshold(100) == 100

    def test_below_minimum(self):
        """Test threshold below minimum raises ValidationError."""
        with pytest.raises(ValidationError, match="must be >= 25"):
            validate_confidence_threshold(24)

        with pytest.raises(ValidationError, match="must be >= 25"):
            validate_confidence_threshold(0)

    def test_above_maximum(self):
        """Test threshold above maximum raises ValidationError."""
        with pytest.raises(ValidationError, match="must be <= 100"):
            validate_confidence_threshold(101)

        with pytest.raises(ValidationError, match="must be <= 100"):
            validate_confidence_threshold(150)

    def test_non_integer_input(self):
        """Test non-integer input raises ValidationError."""
        with pytest.raises(ValidationError, match="must be a number"):
            validate_confidence_threshold("abc")

        with pytest.raises(ValidationError, match="must be a number"):
            validate_confidence_threshold(None)
