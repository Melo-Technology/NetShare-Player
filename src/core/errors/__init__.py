"""Centralized error contracts for API and local GUI consumers."""

from .error_mapper import ApiError, ErrorDomain, ErrorSeverity, map_api_error

__all__ = ["ApiError", "ErrorDomain", "ErrorSeverity", "map_api_error"]
