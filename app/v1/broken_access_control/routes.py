from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.shared.dependencies import FakeDBItem, FakeDBUser
from app.shared.models import Item

router = APIRouter(prefix="/broken-access-control")


# CWE-285 Improper Authorization
@router.get("/cwe-285/items/{id}", response_model=Item)
async def broken_access_control(
    item: FakeDBItem,
    user: FakeDBUser,
):
    if user is None:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "Please log in."},
        )

    if item is None:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND, content={"error": "Item not found."}
        )

    return item
