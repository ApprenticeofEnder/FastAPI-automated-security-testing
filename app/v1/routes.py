import requests
from fastapi import APIRouter

from app.shared.models import SSRFPayload

router = APIRouter(prefix="/v1")


@router.post("/ssrf")
async def ssrf(ssrf_data: SSRFPayload):
    external_res = requests.get(ssrf_data.url)
    data = external_res.json()
    return {"data": data}
