from typing import Annotated

from fastapi import Depends, Header

from app.shared.fake_db import items, users
from app.shared.models import Item, User


async def fake_db_user(
    authorization: Annotated[str | None, Header()] = None,
) -> User | None:
    # Don't ever use this in production, this is for the sake of example
    if authorization is None:
        return None
    bearer = authorization.split(" ")[-1]
    for user in users:
        if user.name == bearer:
            return user
    return None


async def fake_db_item(id: int) -> Item | None:
    try:
        item = items[id]
    except IndexError:
        return None
    return item


FakeDBItem = Annotated[Item | None, Depends(fake_db_item)]
FakeDBUser = Annotated[User | None, Depends(fake_db_user)]
