"""
Custom exceptions for IP reputation checker.
"""


class ValidationError(Exception):
    """Input validation failed (status code 1)."""

    pass


class APIError(Exception):
    """API request failed (status code 2)."""

    pass
