import requests
from fastapi import APIRouter

from app.shared.dependencies import FakeDBItem, FakeDBUser
from app.shared.models import Item, SSRFPayload

router = APIRouter(prefix="/ssrf")


# CWE-918 Server-Side Request Forgery (SSRF)
@router.post("/cwe-918")
async def ssrf(ssrf_data: SSRFPayload):
    external_res = requests.get(ssrf_data.url)
    data = external_res.json()
    return {"data": data}
