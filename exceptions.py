"""
Custom exception hierarchy for the RSC Compliance Report tool.

Using typed exceptions instead of SystemExit means:
  - Callers can catch specific failure modes and clean up (close CSV writers, etc.)
  - Tests can assert on exception type without intercepting process exit
  - Long-running parallel jobs don't abruptly die; main() can log and exit gracefully
"""


class RSCError(Exception):
    """Base class for all RSC Compliance Report errors."""


class RSCAuthError(RSCError):
    """
    Raised when authentication to RSC fails.

    Covers: missing credentials, invalid credentials, token endpoint errors,
    and repeated 401 responses after a token refresh attempt.
    """


class RSCAPIError(RSCError):
    """
    Raised when a GraphQL API call fails unrecoverably.

    Covers: non-retryable HTTP errors, exhausted retry budget, missing data
    in a response that the caller cannot proceed without.
    """


class RSCConfigError(RSCError):
    """
    Raised when the tool is misconfigured.

    Covers: missing required environment variables, invalid configuration
    values detected at startup.
    """
