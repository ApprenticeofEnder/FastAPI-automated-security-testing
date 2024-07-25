import pytest
import responses

LEGIT_URI = "https://xyzcorp.data.com/api/v1/company-data"
LEGIT_RESPONSE = {"message": "Some JSON data!"}
SSRF_URI = "http://192.168.177.14/api/v1/config"
SSRF_RESPONSE = {"application": {"name": "Secret API"}}


@pytest.fixture(autouse=True)
def mock_server():
    responses.start()
    responses.add(
        responses.GET,
        LEGIT_URI,
        json=LEGIT_RESPONSE,
    )
    responses.add(
        responses.GET,
        SSRF_URI,
        json=SSRF_RESPONSE,
    )
    yield
    responses.stop()


@responses.activate
def test_normal_v1(client):
    response = client.post("/v1/ssrf", json={"url": LEGIT_URI})
    assert response.status_code == 200
    assert response.json()["data"] == LEGIT_RESPONSE


@responses.activate
def test_normal_v2(client):
    response = client.post("/v2/ssrf", json={"url": LEGIT_URI})
    assert response.status_code == 200
    assert response.json()["data"] == LEGIT_RESPONSE


@responses.activate
def test_ssrf_v1(client):
    response = client.post("/v1/ssrf", json={"url": SSRF_URI})
    assert response.status_code == 200
    assert (
        response.json()["data"] == SSRF_RESPONSE
    )  # This means we got access to an internal API we definitely shouldn't have.


@responses.activate
def test_ssrf_v2(client):
    response = client.post("/v2/ssrf", json={"url": SSRF_URI})
    assert response.status_code == 400  # This means the SSRF was blocked! Yay!
