from pydantic import BaseModel


class SSRFPayload(BaseModel):
    url: str
