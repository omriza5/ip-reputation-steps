"""
Unit tests for reputation service.
"""

import pytest
from unittest.mock import Mock

from ip_reputation.services.reputation_service import ReputationService
from ip_reputation.models import ReputationData


class TestReputationService:
    """Tests for ReputationService."""

    @pytest.fixture
    def mock_api_client(self):
        """Create mock API client."""
        return Mock()

    @pytest.fixture
    def service(self, mock_api_client):
        """Create service instance with mock client."""
        return ReputationService(api_client=mock_api_client)

    def test_check_ip_high_risk(self, service, mock_api_client):
        """Test IP check with HIGH risk level."""
        # Mock API response
        mock_api_client.check_ip.return_value = {
            "ipAddress": "118.25.6.39",
            "abuseConfidenceScore": 87,
            "totalReports": 1542,
            "countryCode": "CN",
            "isp": "Tencent Cloud Computing",
            "isPublic": True,
        }

        # Call service
        result = service.check_ip("118.25.6.39", confidence_threshold=70)

        # Assertions
        assert isinstance(result, ReputationData)
        assert result.ip == "118.25.6.39"
        assert result.risk_level == "HIGH"
        assert result.abuse_confidence_score == 87
        assert result.total_reports == 1542
        assert result.country_code == "CN"
        assert result.isp == "Tencent Cloud Computing"
        assert result.is_public is True

        # Verify API client was called correctly
        mock_api_client.check_ip.assert_called_once_with("118.25.6.39", 90)

    def test_check_ip_medium_risk(self, service, mock_api_client):
        """Test IP check with MEDIUM risk level."""
        mock_api_client.check_ip.return_value = {
            "ipAddress": "5.6.7.8",
            "abuseConfidenceScore": 50,
            "totalReports": 10,
            "countryCode": "US",
            "isp": "Example ISP",
            "isPublic": True,
        }

        result = service.check_ip("5.6.7.8", confidence_threshold=70)

        assert result.risk_level == "MEDIUM"
        assert result.abuse_confidence_score == 50

    def test_check_ip_low_risk(self, service, mock_api_client):
        """Test IP check with LOW risk level."""
        mock_api_client.check_ip.return_value = {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "countryCode": "US",
            "isp": "Google LLC",
            "isPublic": True,
        }

        result = service.check_ip("8.8.8.8", confidence_threshold=70)

        assert result.risk_level == "LOW"
        assert result.abuse_confidence_score == 0

    def test_check_ip_with_custom_max_age_days(self, service, mock_api_client):
        """Test IP check with custom max_age_days parameter."""
        mock_api_client.check_ip.return_value = {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 10,
            "totalReports": 5,
            "countryCode": "FR",
            "isp": "Test ISP",
            "isPublic": True,
        }

        service.check_ip("1.2.3.4", confidence_threshold=70, max_age_days=30)

        # Verify max_age_days was passed to API client
        mock_api_client.check_ip.assert_called_once_with("1.2.3.4", 30)

    def test_calculate_risk_level_high(self, service):
        """Test risk level calculation for HIGH risk."""
        assert service._calculate_risk_level(70, 70) == "HIGH"
        assert service._calculate_risk_level(100, 70) == "HIGH"
        assert service._calculate_risk_level(85, 50) == "HIGH"

    def test_calculate_risk_level_medium(self, service):
        """Test risk level calculation for MEDIUM risk."""
        assert service._calculate_risk_level(25, 70) == "MEDIUM"
        assert service._calculate_risk_level(50, 70) == "MEDIUM"
        assert service._calculate_risk_level(69, 70) == "MEDIUM"

    def test_calculate_risk_level_low(self, service):
        """Test risk level calculation for LOW risk."""
        assert service._calculate_risk_level(0, 70) == "LOW"
        assert service._calculate_risk_level(10, 70) == "LOW"
        assert service._calculate_risk_level(24, 70) == "LOW"

    def test_calculate_risk_level_boundary_conditions(self, service):
        """Test risk level calculation at boundary values."""
        # Exactly at HIGH threshold
        assert service._calculate_risk_level(70, 70) == "HIGH"

        # Just below HIGH threshold
        assert service._calculate_risk_level(69, 70) == "MEDIUM"

        # Exactly at MEDIUM threshold
        assert service._calculate_risk_level(25, 70) == "MEDIUM"

        # Just below MEDIUM threshold
        assert service._calculate_risk_level(24, 70) == "LOW"