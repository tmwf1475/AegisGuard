from fastapi import FastAPI
from server.detection_adapter import router as detection_router

app = FastAPI()
app.include_router(detection_router, prefix="/detection")
