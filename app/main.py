from fastapi import FastAPI

from app.v1.routes import router as v1_router
from app.v2.routes import router as v2_router

app = FastAPI()
app.include_router(v1_router)
app.include_router(v2_router)
