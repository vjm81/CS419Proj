from app import create_app


def test_health_endpoint():
    app = create_app()
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_basic_frontend_pages_load():
    app = create_app()
    client = app.test_client()

    for path in ("/", "/login", "/register", "/dashboard", "/documents", "/sharing", "/audit"):
        response = client.get(path)
        assert response.status_code == 200
