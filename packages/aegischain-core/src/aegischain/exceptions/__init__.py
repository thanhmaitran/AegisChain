"""Domain-specific exceptions.

Every failure of a security check must surface as one of these (or be recorded as
INDETERMINATE evidence); none may be swallowed into a PASS.
"""


class AegisChainError(Exception):
    """Base class for all AegisChain errors."""


class ValidationError(AegisChainError):
    """Untrusted input failed validation."""


class IngestionError(AegisChainError):
    """Repository ingestion could not be completed safely."""


class ParseError(AegisChainError):
    """A manifest, lockfile or document could not be parsed."""


class ProviderError(AegisChainError):
    """An external intelligence provider failed or returned malformed data."""


class PolicyError(AegisChainError):
    """A security policy is invalid."""


class ArchiveError(ValidationError):
    """An uploaded archive is unsafe or exceeds limits."""
