from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os


def _get_allowed_origins() -> list[str]:
    origins = os.getenv("LOGUI_ALLOWED_ORIGINS", "*")
    # CSV to list, trim whitespace
    parts = [p.strip() for p in origins.split(",") if p.strip()]
    return parts if parts else ["*"]


app = FastAPI(title="AI Proxy Logs UI API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=_get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/ui/health")
async def health_legacy():
    return {"status": "ok"}


@app.get("/ui/v1/health")
async def health_v1():
    return {"status": "ok"}


