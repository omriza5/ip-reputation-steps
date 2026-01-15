"""
Integration tests for batch IP reputation checker CLI.
Follows the design and style of test_check_ip.py.
"""

import pytest
from unittest.mock import patch, Mock

from check_ip_batch.main import read_and_validate_inputs
from ip_reputation.models import ReputationData
from ip_reputation.constants import StatusCode, StatusMessage
from ip_reputation.exceptions import ValidationError, APIError
from ip_reputation.services.reputation_service import ReputationService


class TestReadAndValidateInputs:
    """Tests for read_and_validate_inputs function (batch)."""

    @patch("check_ip_batch.main.os.getenv")
    def test_valid_inputs(self, mock_getenv):
        mock_getenv.side_effect = lambda key, default=None: {
            "IP_ADDRESSES": "8.8.8.8,invalid-ip,1.1.1.1",
            "ABUSEIPDB_API_KEY": "test-key",
            "CONFIDENCE_THRESHOLD": "70",
        }.get(key, default)
        ips, key, threshold = read_and_validate_inputs()
        assert ips == ["8.8.8.8", "invalid-ip", "1.1.1.1"]
        assert key == "test-key"
        assert threshold == 70

    @patch("check_ip_batch.main.os.getenv")
    def test_missing_api_key(self, mock_getenv):
        mock_getenv.side_effect = lambda key, default=None: {
            "IP_ADDRESSES": "8.8.8.8,1.1.1.1",
            "ABUSEIPDB_API_KEY": None,
        }.get(key, default)
        with pytest.raises(ValidationError, match="ABUSEIPDB_API_KEY"):
            read_and_validate_inputs()

    @patch("check_ip_batch.main.os.getenv")
    def test_missing_ip_addresses(self, mock_getenv):
        mock_getenv.side_effect = lambda key, default=None: {
            "IP_ADDRESSES": None,
            "ABUSEIPDB_API_KEY": "test-key",
        }.get(key, default)
        with pytest.raises(ValidationError, match="IP_ADDRESSES"):
            read_and_validate_inputs()

    @patch("check_ip_batch.main.os.getenv")
    def test_invalid_threshold_non_numeric(self, mock_getenv):
        mock_getenv.side_effect = lambda key, default=None: {
            "IP_ADDRESSES": "8.8.8.8,1.1.1.1",
            "ABUSEIPDB_API_KEY": "test-key",
            "CONFIDENCE_THRESHOLD": "hello",
        }.get(key, default)
        with pytest.raises(ValidationError, match="must be a number"):
            read_and_validate_inputs()

    @patch("check_ip_batch.main.os.getenv")
    def test_threshold_below_minimum(self, mock_getenv):
        mock_getenv.side_effect = lambda key, default=None: {
            "IP_ADDRESSES": "8.8.8.8,1.1.1.1",
            "ABUSEIPDB_API_KEY": "test-key",
            "CONFIDENCE_THRESHOLD": "20",
        }.get(key, default)
        with pytest.raises(ValidationError, match="must be >= 25"):
            read_and_validate_inputs()

    @patch("check_ip_batch.main.os.getenv")
    def test_default_threshold(self, mock_getenv):
        mock_getenv.side_effect = lambda key, default=None: {
            "IP_ADDRESSES": "8.8.8.8,1.1.1.1",
            "ABUSEIPDB_API_KEY": "test-key",
            "CONFIDENCE_THRESHOLD": default,
        }.get(key, default)
        ips, key, threshold = read_and_validate_inputs()
        assert threshold == 70


class TestProcessIPBatch:
    """Tests for process_ip_batch function."""

    def test_process_ip_batch_success_and_errors(self):
        # Create a real ReputationService instance with a mock api_client
        service = ReputationService(api_client=Mock())

        # Patch the check_ip method
        service.check_ip = Mock(
            side_effect=[
                ReputationData(
                    ip="8.8.8.8",
                    risk_level="LOW",
                    abuse_confidence_score=0,
                    total_reports=0,
                    country_code="US",
                    isp="Google LLC",
                    is_public=True,
                ),
                APIError("API failed"),
                ReputationData(
                    ip="1.1.1.1",
                    risk_level="LOW",
                    abuse_confidence_score=0,
                    total_reports=0,
                    country_code="AU",
                    isp="Cloudflare, Inc.",
                    is_public=True,
                ),
            ]
        )
        ip_addresses = ["8.8.8.8", "118.25.6.39", "1.1.1.1"]
        confidence_threshold = 50
        results, validation_errors, api_errors = service.process_ip_batch(
            ip_addresses, confidence_threshold
        )
        assert "8.8.8.8" in results
        assert "1.1.1.1" in results
        assert "118.25.6.39" in api_errors or "118.25.6.39" in validation_errors


class TestCalculateSummary:
    """Tests for calculate_summary function."""

    def test_calculate_summary_counts(self):
        results = {
            "8.8.8.8": {"risk_level": "LOW"},
            "1.1.1.1": {"risk_level": "LOW"},
            "118.25.6.39": {"risk_level": "HIGH"},
        }
        errors = {"invalid-ip": "Invalid IP address format"}
        service = ReputationService(api_client=None)
        summary = service._calculate_summary(4, results, errors)
        assert summary["total"] == 4
        assert summary["successful"] == 3
        assert summary["failed"] == 1
        assert summary["risk_counts"]["HIGH"] == 1
        assert summary["risk_counts"]["LOW"] == 2


class TestDetermineStatusMessage:
    """Tests for determine_status_message function."""

    def test_success(self):
        service = ReputationService(api_client=None)
        assert service._determine_status_message(3, 0) == "success"

    def test_partial_success(self):
        service = ReputationService(api_client=None)
        assert service._determine_status_message(2, 1) == "partial_success"

    def test_failed(self):
        service = ReputationService(api_client=None)
        assert service._determine_status_message(0, 2) == "failed"


class TestBuildResponse:
    """Tests for build_response function."""

    def test_build_response_success(self):
        results = {
            "8.8.8.8": {"risk_level": "LOW"},
            "1.1.1.1": {"risk_level": "LOW"},
            "118.25.6.39": {"risk_level": "HIGH"},
        }
        validation_errors = {"invalid-ip": "Invalid IP address format"}
        api_errors = {}
        service = ReputationService(api_client=None)
        response = service.build_batch_ip_response(
            results, validation_errors, api_errors, 4
        )
        assert response["step_status"]["code"] == StatusCode.SUCCESS.value
        assert response["step_status"]["message"] == StatusMessage.SUCCESS.value
        assert response["api_object"]["summary"]["successful"] == 3
        assert response["api_object"]["summary"]["failed"] == 1
        assert "invalid-ip" in response["api_object"]["errors"]

    def test_build_response_partial_success(self):
        results = {
            "8.8.8.8": {"risk_level": "LOW"},
        }
        validation_errors = {"invalid-ip": "Invalid IP address format"}
        api_errors = {"118.25.6.39": "API failed"}
        service = ReputationService(api_client=None)
        response = service.build_batch_ip_response(
            results, validation_errors, api_errors, 3
        )
        assert response["step_status"]["code"] == StatusCode.SUCCESS.value
        assert response["step_status"]["message"] == StatusMessage.PARTIAL_SUCCESS.value
        assert response["api_object"]["summary"]["successful"] == 1
        assert response["api_object"]["summary"]["failed"] == 2
        assert "invalid-ip" in response["api_object"]["errors"]
        assert "118.25.6.39" in response["api_object"]["errors"]
