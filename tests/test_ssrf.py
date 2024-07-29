import pytest
import responses

LEGIT_URI = "https://xyzcorp.data.com/api/v1/company-data"
LEGIT_RESPONSE = {"message": "Some JSON data!"}
SSRF_URI = "http://192.168.177.14/api/v1/config"
SSRF_RESPONSE = {"application": {"name": "Secret API"}}


@pytest.fixture
def v1_base_endpoint():
    return "/v1/ssrf"


@pytest.fixture
def v2_base_endpoint():
    return "/v2/ssrf"


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


class TestSSRF:

    # CWE-918 Server-Side Request Forgery (SSRF)
    @responses.activate
    def test_cwe_918_v1(self, client, v1_base_endpoint):
        response = client.post(f"{v1_base_endpoint}/cwe-918", json={"url": LEGIT_URI})
        assert response.status_code == 200
        assert response.json()["data"] == LEGIT_RESPONSE

        response = client.post(f"{v1_base_endpoint}/cwe-918", json={"url": SSRF_URI})
        assert response.status_code == 200
        assert (
            response.json()["data"] == SSRF_RESPONSE
        )  # This means we got access to an internal API we definitely shouldn't have.

    @responses.activate
    def test_cwe_918_v2(self, client, v2_base_endpoint):
        response = client.post(f"{v2_base_endpoint}/cwe-918", json={"url": LEGIT_URI})
        assert response.status_code == 200
        assert response.json()["data"] == LEGIT_RESPONSE

        response = client.post(f"{v2_base_endpoint}/cwe-918", json={"url": SSRF_URI})
        assert response.status_code == 400  # This means the SSRF was blocked! Yay!
