from urllib.parse import urlencode

import pytest
from pydantic import BaseModel


class Profiles(BaseModel):
    alpha: str
    beta: str


@pytest.fixture
def v1_base_endpoint():
    return "/v1/broken-access-control"


@pytest.fixture
def v2_base_endpoint():
    return "/v2/broken-access-control"


@pytest.fixture
def profile_alpha_filename():
    return "profiles/alpha.json"


@pytest.fixture
def profile_beta_filename():
    return "profiles/beta.json"


@pytest.fixture
def profiles(profile_alpha_filename, profile_beta_filename):
    alpha = open(profile_alpha_filename).read()
    beta = open(profile_beta_filename).read()
    return Profiles(alpha=alpha, beta=beta)


class TestBrokenAccessControl:

    # CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    def test_cwe_22_v1(
        self,
        client,
        v1_base_endpoint,
        profiles,
        profile_alpha_filename,
    ):
        params = {"profile": profile_alpha_filename}

        response = client.get(
            f"{v1_base_endpoint}/cwe-22?{urlencode(params)}",
        )
        assert response.status_code == 200
        assert response.json()["profile"] == profiles.alpha

        params = {"profile": "/etc/passwd"}

        response = client.get(
            f"{v1_base_endpoint}/cwe-22?{urlencode(params)}",
        )
        assert response.status_code == 200
        assert response.json()["profile"] == open("/etc/passwd").read()

    def test_cwe_22_v2(self, client, v2_base_endpoint, profiles, profile_beta_filename):
        params = {"profile": profile_beta_filename}

        response = client.get(
            f"{v2_base_endpoint}/cwe-22?{urlencode(params)}",
        )
        assert response.status_code == 200
        assert response.json()["profile"] == profiles.beta

        params = {"profile": "/etc/passwd"}

        response = client.get(
            f"{v1_base_endpoint}/cwe-22?{urlencode(params)}",
        )
        assert response.status_code == 404

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
