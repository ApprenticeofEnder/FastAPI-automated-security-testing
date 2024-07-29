import re
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, Response, status

from app.shared.dependencies import FakeDBItem, FakeDBUser
from app.shared.models import Item, SSRFPayload

router = APIRouter(prefix="/ssrf")

valid_domain_re = re.compile(r".*\.data\.com", flags=re.IGNORECASE)


# CWE-918 Server-Side Request Forgery (SSRF)
@router.post("/cwe-918")
async def ssrf(ssrf_data: SSRFPayload, response: Response):
    parsed_url = urlparse(ssrf_data.url)
    if valid_domain_re.match(parsed_url.netloc) is None or parsed_url.scheme != "https":
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"error": "Invalid URL provided."}
    external_res = requests.get(parsed_url.geturl())
    data = external_res.json()
    return {"data": data}
