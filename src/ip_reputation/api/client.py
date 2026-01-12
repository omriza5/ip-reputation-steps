"""
AbuseIPDB API client.
"""

import httpx
from http import HTTPStatus
from ip_reputation.constants import (
    ABUSEIPDB_API_BASE_URL,
    ABUSEIPDB_CHECK_ENDPOINT,
    API_TIMEOUT_SECONDS,
    DEFAULT_MAX_AGE_DAYS,
)
from ip_reputation.exceptions import APIError


class AbuseIPDBClient:
    """Client for interacting with AbuseIPDB API."""

    def __init__(self, api_key: str):
        """
        Args:
            api_key: AbuseIPDB API key
        """
        self.api_key = api_key
        self.base_url = ABUSEIPDB_API_BASE_URL
        self.timeout = API_TIMEOUT_SECONDS

    def check_ip(
        self, ip_address: str, max_age_days: int = DEFAULT_MAX_AGE_DAYS
    ) -> dict[str, any]:
        """
        Check IP address reputation.

        Args:
            ip_address: IP address to check
            max_age_days: Maximum age of reports to consider (default: 90)

        Returns:
            Dictionary containing API response data

        Raises:
            APIError: If API request fails
        """
        url = f"{self.base_url}{ABUSEIPDB_CHECK_ENDPOINT}"

        headers = {"Accept": "application/json", "Key": self.api_key}

        params = {"ipAddress": ip_address, "maxAgeInDays": max_age_days}

        try:
            response = httpx.get(
                url, headers=headers, params=params, timeout=self.timeout
            )

            # Handle specific HTTP errors
            if response.status_code == HTTPStatus.UNAUTHORIZED:
                raise APIError("Authentication failed. Invalid API key.")

            if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                raise APIError("Rate limit exceeded. Please try again later.")

            if response.status_code != HTTPStatus.OK:
                raise APIError(
                    f"API request failed with status {response.status_code}: {response.text}"
                )

            # Parse and return data
            data = response.json()
            return data.get("data", {})

        except APIError:
            raise

        except httpx.TimeoutException:
            raise APIError(f"Request timeout after {self.timeout} seconds")

        except httpx.NetworkError as e:
            raise APIError(f"Network error: {str(e)}")

        except httpx.HTTPError as e:
            raise APIError(f"HTTP error: {str(e)}")

        except Exception as e:
            # Catch any other unexpected errors (JSON parsing, etc.)
            raise APIError(f"Unexpected error: {str(e)}")
