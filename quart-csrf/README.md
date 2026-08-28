# Quart-CSRF

A lightweight, secure, and asynchronous CSRF protection extension for [Quart](https://github.com/pallets/quart) web applications.

## Features

- **Automatic Token Ingestion**: Supports CSRF token retrieval from `X-CSRF-Token` headers, JSON request bodies, and form data.
- **Timing Attack Safe**: Uses `hmac.compare_digest` for secure token validation.
- **Auto Injection**: Optionally injects meta tags and hidden inputs into HTML responses.
- **API Friendly**: Returns structured JSON error responses for API endpoints.
- **View Exemption**: Easy decorator to exempt specific routes.

## Installation

```bash
pip install quart-csrf
```

## Quick Start

```python
from quart import Quart, render_template_string
from quart_csrf import CSRFProtect

app = Quart(__name__)
app.secret_key = "super-secret-key"

csrf = CSRFProtect(app)

@app.route("/", methods=["GET", "POST"])
async def index():
    return await render_template_string("""
        <!DOCTYPE html>
        <html>
        <head><title>CSRF Test</title></head>
        <body>
            <form method="POST">
                <button type="submit">Submit</button>
            </form>
        </body>
        </html>
    """)

@app.route("/api/data", methods=["POST"])
@csrf.exempt
async def api_data():
    return {"status": "success"}

if __name__ == "__main__":
    app.run()
```

## Testing

Run tests using `pytest`:

```bash
pytest
```

## License

MIT License
