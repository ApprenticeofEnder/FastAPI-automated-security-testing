import os
from pathlib import Path

from fastapi import APIRouter, Response, status
from fastapi.responses import JSONResponse

from app.shared.dependencies import FakeDBItem, FakeDBUser
from app.shared.models import Item

router = APIRouter(prefix="/broken-access-control")


# CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
@router.get("/cwe-22")
async def cwe_22_path_traversal(profile: str, response: Response):
    try:
        with open(os.path.join(os.getcwd(), profile), "r") as file:
            return {"profile": file.read()}
    except FileNotFoundError:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"error": "Profile not found."}


# CWE-23 Relative Path Traversal
@router.get("/cwe-23")
async def cwe_23_path_traversal(profile: str, response: Response):
    try:
        # Credit for this goes to Maarten Fabré on StackOverflow:
        # https://stackoverflow.com/questions/45188708/how-to-prevent-directory-traversal-attack-from-python-code
        root_dir = Path(os.getcwd())
        with open(
            root_dir.joinpath(profile).resolve().relative_to(root_dir.resolve()), "r"
        ) as file:
            return {"profile": file.read()}
    except ValueError:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"error": "Profile not found."}
    except FileNotFoundError:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"error": "Error processing request."}


# CWE-285 Improper Authorization
@router.get("/cwe-285/items/{id}", response_model=Item)
async def cwe_285_improper_authorization(
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

    if user.id != item.owner_id:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "You can't access that item."},
        )

    return item
