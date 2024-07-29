from pydantic import BaseModel


class SSRFPayload(BaseModel):
    url: str


class Item(BaseModel):
    id: int
    name: str
    owner_id: int


class User(BaseModel):
    id: int
    name: str
    items: list["Item"] = []
