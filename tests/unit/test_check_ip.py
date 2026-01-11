"""
Integration tests for single IP checker CLI.
"""

import pytest
from unittest.mock import patch

from check_ip.main import (
    read_and_validate_inputs,
    build_success_response,
    build_error_response,
)
from ip_reputation.models import ReputationData
from ip_reputation.constants import StatusCode
from ip_reputation.exceptions import ValidationError


class TestReadAndValidateInputs:
    """Tests for read_and_validate_inputs function."""

    @patch("check_ip.main.os.getenv")
    def test_valid_inputs(self, mock_getenv):
        """Test with valid environment variables."""
        mock_getenv.side_effect = lambda key, default=None: {
            "IP_ADDRESS": "8.8.8.8",
            "ABUSEIPDB_API_KEY": "test-api-key",
            "CONFIDENCE_THRESHOLD": "70",
        }.get(key, default)

        ip, key, threshold = read_and_validate_inputs()

        assert ip == "8.8.8.8"
        assert key == "test-api-key"
        assert threshold == 70

    @patch("check_ip.main.os.getenv")
    def test_missing_api_key(self, mock_getenv):
        """Test missing API key raises ValidationError."""
        mock_getenv.side_effect = lambda key, default=None: {
            "IP_ADDRESS": "8.8.8.8",
            "ABUSEIPDB_API_KEY": None,
        }.get(key, default)

        with pytest.raises(ValidationError, match="ABUSEIPDB_API_KEY"):
            read_and_validate_inputs()

    @patch("check_ip.main.os.getenv")
    def test_missing_ip_address(self, mock_getenv):
        """Test missing IP address raises ValidationError."""
        mock_getenv.side_effect = lambda key, default=None: {
            "IP_ADDRESS": None,
            "ABUSEIPDB_API_KEY": "test-key",
        }.get(key, default)

        with pytest.raises(ValidationError, match="IP_ADDRESS"):
            read_and_validate_inputs()

    @patch("check_ip.main.os.getenv")
    def test_invalid_ip_format(self, mock_getenv):
        """Test invalid IP format raises ValidationError."""
        mock_getenv.side_effect = lambda key, default=None: {
            "IP_ADDRESS": "invalid-ip",
            "ABUSEIPDB_API_KEY": "test-key",
        }.get(key, default)

        with pytest.raises(ValidationError, match="Invalid IP address format"):
            read_and_validate_inputs()

    @patch("check_ip.main.os.getenv")
    def test_invalid_threshold_non_numeric(self, mock_getenv):
        """Test non-numeric threshold raises ValidationError."""
        mock_getenv.side_effect = lambda key, default=None: {
            "IP_ADDRESS": "8.8.8.8",
            "ABUSEIPDB_API_KEY": "test-key",
            "CONFIDENCE_THRESHOLD": "hello",
        }.get(key, default)

        with pytest.raises(ValidationError, match="must be a number"):
            read_and_validate_inputs()

    @patch("check_ip.main.os.getenv")
    def test_threshold_below_minimum(self, mock_getenv):
        """Test threshold below minimum raises ValidationError."""
        mock_getenv.side_effect = lambda key, default=None: {
            "IP_ADDRESS": "8.8.8.8",
            "ABUSEIPDB_API_KEY": "test-key",
            "CONFIDENCE_THRESHOLD": "20",
        }.get(key, default)

        with pytest.raises(ValidationError, match="must be >= 25"):
            read_and_validate_inputs()

    @patch("check_ip.main.os.getenv")
    def test_default_threshold(self, mock_getenv):
        """Test default threshold is used when not provided."""
        mock_getenv.side_effect = lambda key, default=None: {
            "IP_ADDRESS": "8.8.8.8",
            "ABUSEIPDB_API_KEY": "test-key",
            "CONFIDENCE_THRESHOLD": default,
        }.get(key, default)

        ip, key, threshold = read_and_validate_inputs()

        assert threshold == 70  # Default value


class TestBuildSuccessResponse:
    """Tests for build_success_response function."""

    def test_builds_correct_structure(self):
        """Test success response has correct structure."""
        reputation_data = ReputationData(
            ip="8.8.8.8",
            risk_level="LOW",
            abuse_confidence_score=0,
            total_reports=0,
            country_code="US",
            isp="Google LLC",
            is_public=True,
        )

        response = build_success_response(reputation_data)

        assert response["step_status"]["code"] == 0
        assert response["step_status"]["message"] == "success"
        assert response["api_object"]["ip"] == "8.8.8.8"
        assert response["api_object"]["risk_level"] == "LOW"
        assert response["api_object"]["abuse_confidence_score"] == 0


class TestBuildErrorResponse:
    """Tests for build_error_response function."""

    def test_validation_error_response(self):
        """Test validation error response structure."""
        error = ValidationError("Invalid input")
        response = build_error_response(error, StatusCode.VALIDATION_ERROR)

        assert response["step_status"]["code"] == 1
        assert response["step_status"]["message"] == "failed"
        assert response["api_object"]["error"] == "Invalid input"

    def test_api_error_response(self):
        """Test API error response structure."""
        error = Exception("API failed")
        response = build_error_response(error, StatusCode.API_ERROR)

        assert response["step_status"]["code"] == 2
        assert response["step_status"]["message"] == "failed"
        assert response["api_object"]["error"] == "API failed"
