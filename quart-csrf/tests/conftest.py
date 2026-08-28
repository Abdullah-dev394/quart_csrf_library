import pytest
from quart import Quart


@pytest.fixture
def app():
    app = Quart(__name__)
    app.secret_key = "test-secret-key"
    return app
