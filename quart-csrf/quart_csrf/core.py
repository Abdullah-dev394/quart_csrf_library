import hmac
import inspect
import re
import secrets
from typing import Any, Callable, Optional

from quart import Quart, current_app, request, session
from quart.wrappers import Response

from .exceptions import CSRFError


class CSRFProtect:
    """CSRF protection extension for Quart applications."""

    _HEAD_END_RE = re.compile(r"</head\s*>", re.IGNORECASE)
    _FORM_END_RE = re.compile(r"</form\s*>", re.IGNORECASE)

    def __init__(self, app: Optional[Quart] = None, input_auto_injecting: bool = True) -> None:
        self._input_auto_injecting = input_auto_injecting
        if app is not None:
            self.init_app(app)

    def exempt(self, view_func: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator to exempt a view function from CSRF protection."""
        view_func._csrf_exempt = True  # type: ignore[attr-defined]
        return view_func

    def init_app(self, app: Quart) -> None:
        """Initialize the extension with a Quart application instance."""

        @app.errorhandler(CSRFError)
        def handle_csrf_error(e: CSRFError) -> Any:
            is_api = (
                request.is_json
                or "application/json" in request.headers.get("Accept", "")
                or request.path.startswith("/api/")
            )

            if is_api:
                return {
                    "error": "CSRFValidationError",
                    "message": e.description,
                    "status": 400,
                }, 400

            return e.description, 400

        app.before_request(self._check_token)
        app.after_request(self._add_csrf_token)
        app.jinja_env.globals["csrf_token"] = self._generate_token

    def _generate_token(self) -> str:
        """Generate or retrieve the CSRF token stored in the session."""
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(16)
        return session["csrf_token"]

    async def _check_token(self) -> None:
        """Verify the CSRF token for non-safe HTTP methods."""
        if request.method not in ("GET", "HEAD", "OPTIONS", "TRACE"):
            endpoint = request.endpoint

            if endpoint and endpoint in current_app.view_functions:
                view_func = current_app.view_functions[endpoint]
                if getattr(view_func, "_csrf_exempt", False):
                    return

            csrf_token = self._generate_token()
            input_token = request.headers.get("X-CSRF-Token")

            if not input_token:
                content_type = request.content_type or ""
                if "application/json" in content_type:
                    try:
                        json_data = await request.get_json()
                        if json_data and isinstance(json_data, dict):
                            input_token = json_data.get("csrf_token")
                    except Exception:
                        pass
                elif (
                    "multipart/form-data" in content_type
                    or "application/x-www-form-urlencoded" in content_type
                ):
                    data = await request.form
                    input_token = data.get("csrf_token")

            if not input_token or not hmac.compare_digest(
                csrf_token, input_token
            ):
                raise CSRFError()

    async def _add_csrf_token(self, response: Response) -> Response:
        """Add CSRF response headers and auto-inject CSRF tokens into HTML."""
        token = self._generate_token()
        response.headers["X-CSRF-Token"] = token
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Vary"] = "Cookie"
        response.headers["X-Content-Type-Options"] = "nosniff"

        if getattr(response, "is_streamed", False):
            return response

        if response.content_type and "text/html" in response.content_type:
            data = response.get_data()
            if inspect.isawaitable(data):
                data = await data
            data_str = data.decode("utf-8", errors="replace")

            if self._input_auto_injecting:
                if (
                    "<head" in data_str.lower()
                    and 'name="csrf_token"' not in data_str
                ):
                    meta_tag = f'<meta name="csrf_token" content="{token}">'
                    data_str = self._HEAD_END_RE.sub(
                        f"{meta_tag}\n</head>", data_str, count=1
                    )

                if "<form" in data_str.lower():
                    if 'name="csrf_token"' not in data_str:
                        hidden_input = (
                            f'<input type="hidden" name="csrf_token" value="{token}">'
                        )
                        data_str = self._FORM_END_RE.sub(
                            f"{hidden_input}\n</form>", data_str
                        )

            response.set_data(data_str.encode("utf-8"))

        return response
