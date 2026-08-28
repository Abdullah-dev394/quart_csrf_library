import pytest
from quart import Quart, jsonify, request
from quart_csrf import CSRFError, CSRFProtect


@pytest.mark.asyncio
async def test_get_request_generates_token(app: Quart):
    CSRFProtect(app)

    @app.route("/test", methods=["GET"])
    async def index():
        return "OK"

    client = app.test_client()
    response = await client.get("/test")
    assert response.status_code == 200
    assert "X-CSRF-Token" in response.headers


@pytest.mark.asyncio
async def test_post_without_token_fails(app: Quart):
    CSRFProtect(app)

    @app.route("/submit", methods=["POST"])
    async def submit():
        return "Success"

    client = app.test_client()
    response = await client.post("/submit")
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_post_with_valid_header_token_succeeds(app: Quart):
    CSRFProtect(app)

    @app.route("/action", methods=["GET", "POST"])
    async def action():
        return "OK"

    client = app.test_client()
    get_res = await client.get("/action")
    token = get_res.headers.get("X-CSRF-Token")

    post_res = await client.post("/action", headers={"X-CSRF-Token": token})
    assert post_res.status_code == 200


@pytest.mark.asyncio
async def test_exempt_route(app: Quart):
    csrf = CSRFProtect(app)

    @app.route("/unprotected", methods=["POST"])
    @csrf.exempt
    async def unprotected():
        return "Unprotected"

    client = app.test_client()
    response = await client.post("/unprotected")
    assert response.status_code == 200


if __name__ == "__main__":
    import sys
    import pytest

    sys.exit(pytest.main(["-v", __file__]))