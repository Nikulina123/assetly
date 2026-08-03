from fastapi import FastAPI

from app.routers.checkin import router as checkin_router

app = FastAPI(title="Webiz Inventory Check-in API")
app.include_router(checkin_router)
