class AppException(Exception):
    """Base exception class for all domain-specific application errors.

    Every domain exception in the project must inherit from this class.
    The global exception handler in ``main.py`` catches ``AppException``
    and converts it into a consistent JSON error response.

    Attributes:
        message: Human-readable error description.
        error_code: Machine-readable identifier (e.g., ``"USER_NOT_FOUND"``).
        status_code: HTTP status code to return in the API response.
    """

    def __init__(self, message: str, error_code: str, status_code: int = 500):
        """Initializes the base application exception.

        Args:
            message: Human-readable error description.
            error_code: Machine-readable error identifier.
            status_code: HTTP status code. Defaults to ``500``.
        """
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(self.message)


class NotFoundException(AppException):
    """Raised when a requested entity does not exist in the database.

    Produces HTTP ``404 Not Found`` with an error code formatted as
    ``"{ENTITY}_NOT_FOUND"`` (e.g., ``"USER_NOT_FOUND"``).
    """

    def __init__(self, entity: str, identifier: str):
        """Initializes the not-found exception.

        Args:
            entity: The type of entity that was not found (e.g., ``"User"``).
            identifier: The identifier used in the failed lookup.
        """
        super().__init__(
            message=f"{entity} with identifier '{identifier}' was not found.",
            error_code=f"{entity.upper()}_NOT_FOUND",
            status_code=404,
        )


class AlreadyExistsException(AppException):
    """Raised when attempting to create an entity that violates a uniqueness constraint.

    Produces HTTP ``409 Conflict`` with an error code formatted as
    ``"{ENTITY}_ALREADY_EXISTS"`` (e.g., ``"USER_ALREADY_EXISTS"``).
    """

    def __init__(self, entity: str, field: str, value: str):
        """Initializes the already-exists exception.

        Args:
            entity: The type of entity that already exists (e.g., ``"User"``).
            field: The field that caused the conflict (e.g., ``"email"``).
            value: The conflicting value.
        """
        super().__init__(
            message=f"{entity} with {field} '{value}' already exists.",
            error_code=f"{entity.upper()}_ALREADY_EXISTS",
            status_code=409,
        )


class AccessDeniedException(AppException):
    """Raised when a user lacks permission to perform an action.

    Produces HTTP ``403 Forbidden``.
    """

    def __init__(self, message: str = "Access denied."):
        """Initializes the access-denied exception.

        Args:
            message: Custom denial message. Defaults to ``"Access denied."``.
        """
        super().__init__(
            message=message,
            error_code="ACCESS_DENIED",
            status_code=403,
        )


class PermissionDeniedException(AppException):
    """Raised when a user lacks permission to perform an action.

    Produces HTTP ``403 Forbidden``.
    """

    def __init__(self, message: str = "Permission denied."):
        """Initializes the permission-denied exception.

        Args:
            message: Custom denial message. Defaults to ``"Permission denied."``.
        """
        super().__init__(
            message=message,
            error_code="PERMISSION_DENIED",
            status_code=403,
        )


class InactiveEntityException(AppException):
    """Raised when operating on a soft-deleted or deactivated entity.

    Produces HTTP ``403 Forbidden`` with an error code formatted as
    ``"{ENTITY}_INACTIVE"`` (e.g., ``"USER_INACTIVE"``).
    """

    def __init__(self, entity: str, identifier: str):
        """Initializes the inactive-entity exception.

        Args:
            entity: The type of entity that is inactive (e.g., ``"User"``).
            identifier: The identifier of the inactive entity.
        """
        super().__init__(
            message=f"{entity} with identifier '{identifier}' is inactive.",
            error_code=f"{entity.upper()}_INACTIVE",
            status_code=403,
        )


class InvalidCredentialsException(AppException):
    """Raised when login credentials are incorrect or a JWT token is invalid.

    Produces HTTP ``401 Unauthorized``.
    """

    def __init__(self, message: str = "Invalid email or password."):
        """Initializes the invalid-credentials exception."""
        super().__init__(
            message=message,
            error_code="INVALID_CREDENTIALS",
            status_code=401,
        )


class TokenExpiredException(InvalidCredentialsException):
    """Raised when a JWT access or refresh token has expired.

    Produces HTTP ``401 Unauthorized``.
    """

    def __init__(self, message: str = "Token has expired."):
        """Initializes the token-expired exception."""
        super().__init__(message=message)
        self.error_code = "TOKEN_EXPIRED"


class TokenRevokedException(AppException):
    """Raised when a refresh token has been revoked or does not exist.

    Produces HTTP ``401 Unauthorized``.
    """

    def __init__(self, message: str = "Refresh token has been revoked or is invalid."):
        """Initializes the token-revoked exception."""
        super().__init__(
            message=message,
            error_code="TOKEN_REVOKED",
            status_code=401,
        )


class TokenStaleException(AppException):
    """Raised when an access token security version does not match the user's current version.

    Produces HTTP ``401 Unauthorized``.
    """

    def __init__(self, message: str = "Session has been invalidated due to credential changes. Please log in again."):
        """Initializes the token-stale exception."""
        super().__init__(
            message=message,
            error_code="TOKEN_STALE",
            status_code=401,
        )
