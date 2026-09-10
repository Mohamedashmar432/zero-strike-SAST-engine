# Phase 1 (file role) + Phase 2 (retired assert rule).
#
# A pytest module. Every line below is how the framework expresses a test, and
# a scan of one real repository reported 1300 findings across files exactly
# like this one. This file must produce nothing: it sits in a tests/ path, and
# the assert rule that flagged it is retired.
import pytest

ADMIN_PASSWORD = "test-user-password"
API_TOKEN = "test-token-value"


def test_login(client):
    response = client.post("/login", json={"password": ADMIN_PASSWORD})
    assert response.status_code == 200
    assert response.json()["token"] != ""
    assert API_TOKEN not in response.text


def test_admin_guard(client):
    assert client.get("/admin").status_code == 403
