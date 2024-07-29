import pytest


@pytest.fixture
def v1_base_endpoint():
    return "/v1/broken-access-control"


@pytest.fixture
def v2_base_endpoint():
    return "/v2/broken-access-control"


class TestBrokenAccessControl:

    # CWE-285 Improper Authorization
    def test_cwe_285_invalid(self, client, v1_base_endpoint, v2_base_endpoint):
        for base_endpoint in [v1_base_endpoint, v2_base_endpoint]:
            response = client.get(
                f"{base_endpoint}/cwe-285/items/2",
                headers={"Authorization": "Bearer Jeremy"},
            )
            assert response.status_code == 404

            response = client.get(
                f"{base_endpoint}/cwe-285/items/0",
                headers={"Authorization": "Bearer John"},
            )
            assert response.status_code == 401

            response = client.get(
                f"{base_endpoint}/cwe-285/items/0",
            )
            assert response.status_code == 401

    def test_cwe_285_v1(self, client, v1_base_endpoint):
        response = client.get(
            f"{v1_base_endpoint}/cwe-285/items/0",
            headers={"Authorization": "Bearer Jeremy"},
        )
        assert response.status_code == 200

        response = client.get(
            f"{v1_base_endpoint}/cwe-285/items/0",
            headers={"Authorization": "Bearer Fatima"},
        )
        assert response.status_code == 200

        response = client.get(
            f"{v1_base_endpoint}/cwe-285/items/1",
            headers={"Authorization": "Bearer Jeremy"},
        )
        assert response.status_code == 200

        response = client.get(
            f"{v1_base_endpoint}/cwe-285/items/1",
            headers={"Authorization": "Bearer Fatima"},
        )
        assert response.status_code == 200

    def test_cwe_285_v2(self, client, v2_base_endpoint):
        response = client.get(
            f"{v2_base_endpoint}/cwe-285/items/0",
            headers={"Authorization": "Bearer Jeremy"},
        )
        assert response.status_code == 200

        response = client.get(
            f"{v2_base_endpoint}/cwe-285/items/0",
            headers={"Authorization": "Bearer Fatima"},
        )
        assert response.status_code == 403

        response = client.get(
            f"{v2_base_endpoint}/cwe-285/items/1",
            headers={"Authorization": "Bearer Jeremy"},
        )
        assert response.status_code == 403

        response = client.get(
            f"{v2_base_endpoint}/cwe-285/items/1",
            headers={"Authorization": "Bearer Fatima"},
        )
        assert response.status_code == 200
