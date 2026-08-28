from werkzeug.exceptions import BadRequest


class CSRFError(BadRequest):
    """Exception raised when a CSRF token is missing or invalid."""

    description = "CSRF token missing or invalid"
