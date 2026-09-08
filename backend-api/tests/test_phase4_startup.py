"""Start the real application/router stack with no separately running services."""

from fastapi.testclient import TestClient

from app.main import create_app


def test_application_startup_and_public_health():
    with TestClient(create_app()) as client:
        assert client.get("/").json() == {
            "status": "ok",
            "message": "AutoAudit API running",
        }
        response = client.get("/liveness")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}
        assert client.get("/openapi.json").status_code == 200
        assert client.get("/v1/scans/").status_code == 401
