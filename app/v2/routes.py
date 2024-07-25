import re
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, Response, status

from app.shared.models import SSRFPayload

router = APIRouter(prefix="/v2")

valid_domain_re = re.compile(r".*\.data\.com", flags=re.IGNORECASE)


@router.post("/ssrf")
async def ssrf(ssrf_data: SSRFPayload, response: Response):
    parsed_url = urlparse(ssrf_data.url)
    if valid_domain_re.match(parsed_url.netloc) is None or parsed_url.scheme != "https":
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"error": "Invalid URL provided."}
    external_res = requests.get(parsed_url.geturl())
    data = external_res.json()
    return {"data": data}
