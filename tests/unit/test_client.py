"""
Unit tests for AbuseIPDB API client.
"""

import pytest
from unittest.mock import Mock, patch
from http import HTTPStatus
import httpx

from ip_reputation.api.client import AbuseIPDBClient
from ip_reputation.exceptions import APIError


class TestAbuseIPDBClient:
    """Tests for AbuseIPDBClient."""

    @pytest.fixture
    def client(self):
        """Create client instance for testing."""
        return AbuseIPDBClient(api_key="test-api-key")

    @patch("ip_reputation.api.client.httpx.get")
    def test_check_ip_success(self, mock_get, client):
        """Test successful IP check."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = HTTPStatus.OK
        mock_response.json.return_value = {
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "countryCode": "US",
                "isp": "Google LLC",
                "isPublic": True,
            }
        }
        mock_get.return_value = mock_response

        # Call method
        result = client.check_ip("8.8.8.8")

        # Assertions
        assert result["ipAddress"] == "8.8.8.8"
        assert result["abuseConfidenceScore"] == 0
        assert result["countryCode"] == "US"

        # Verify correct API call
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args.kwargs
        assert call_kwargs["params"]["ipAddress"] == "8.8.8.8"
        assert call_kwargs["headers"]["Key"] == "test-api-key"

    @patch("ip_reputation.api.client.httpx.get")
    def test_check_ip_with_max_age_days(self, mock_get, client):
        """Test IP check with custom max_age_days."""
        mock_response = Mock()
        mock_response.status_code = HTTPStatus.OK
        mock_response.json.return_value = {"data": {}}
        mock_get.return_value = mock_response

        client.check_ip("1.2.3.4", max_age_days=30)

        call_kwargs = mock_get.call_args.kwargs
        assert call_kwargs["params"]["maxAgeInDays"] == 30

    @patch("ip_reputation.api.client.httpx.get")
    def test_unauthorized_error(self, mock_get, client):
        """Test 401 unauthorized error."""
        mock_response = Mock()
        mock_response.status_code = HTTPStatus.UNAUTHORIZED
        mock_get.return_value = mock_response

        with pytest.raises(APIError, match="Authentication failed"):
            client.check_ip("8.8.8.8")

    @patch("ip_reputation.api.client.httpx.get")
    def test_rate_limit_error(self, mock_get, client):
        """Test 429 rate limit error."""
        mock_response = Mock()
        mock_response.status_code = HTTPStatus.TOO_MANY_REQUESTS
        mock_get.return_value = mock_response

        with pytest.raises(APIError, match="Rate limit exceeded"):
            client.check_ip("8.8.8.8")

    @patch("ip_reputation.api.client.httpx.get")
    def test_other_http_error(self, mock_get, client):
        """Test other HTTP error (e.g., 500)."""
        mock_response = Mock()
        mock_response.status_code = HTTPStatus.INTERNAL_SERVER_ERROR
        mock_response.text = "Server error"
        mock_get.return_value = mock_response

        with pytest.raises(APIError, match="API request failed with status 500"):
            client.check_ip("8.8.8.8")

    @patch("ip_reputation.api.client.httpx.get")
    def test_timeout_error(self, mock_get, client):
        """Test request timeout."""
        mock_get.side_effect = httpx.TimeoutException("Timeout")

        with pytest.raises(APIError, match="Request timeout"):
            client.check_ip("8.8.8.8")

    @patch("ip_reputation.api.client.httpx.get")
    def test_network_error(self, mock_get, client):
        """Test network error."""
        mock_get.side_effect = httpx.NetworkError("Connection failed")

        with pytest.raises(APIError, match="Network error"):
            client.check_ip("8.8.8.8")

    @patch("ip_reputation.api.client.httpx.get")
    def test_unexpected_error(self, mock_get, client):
        """Test unexpected error handling."""
        mock_response = Mock()
        mock_response.status_code = HTTPStatus.OK
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response

        with pytest.raises(APIError, match="Unexpected error"):
            client.check_ip("8.8.8.8")
