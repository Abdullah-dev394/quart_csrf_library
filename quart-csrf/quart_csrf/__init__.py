"""Quart-CSRF: CSRF protection extension for Quart applications."""

from .core import CSRFProtect
from .exceptions import CSRFError

__version__ = "0.1.0"
__all__ = ["CSRFProtect", "CSRFError"]
