from fastapi import APIRouter

from app.v1.broken_access_control import router as broken_access_control_router
from app.v1.ssrf import router as ssrf_router

router = APIRouter(prefix="/v1")
router.include_router(broken_access_control_router)
router.include_router(ssrf_router)
