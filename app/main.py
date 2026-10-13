import os
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.services.redis_service import redis_service
from app.services.alert_service import alert_ws_manager
from app.api.routes_check import router as check_router
from app.api.routes_stats import router as stats_router
from app.api.routes_blacklist import router as blacklist_router
from app.api.routes_alerts import router as alerts_router
from app.api.routes_settings import router as settings_router
from app.api.routes_benchmark import router as benchmark_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Threat Intelligence Cache System...")
    # 1. Connect Redis
    await redis_service.connect()
    # 2. Start background Pub/Sub listener for WebSockets
    alert_ws_manager.start_background_listener()
    logger.info("Application startup sequence completed.")

    yield

    logger.info("Initiating application shutdown sequence...")
    await alert_ws_manager.stop()
    await redis_service.disconnect()
    logger.info("Application shutdown completed.")


app = FastAPI(
    title=settings.APP_NAME,
    description="Production-Grade Real-Time Threat Intelligence Cache and Malicious URL/IP Detection System Using Redis",
    version="1.0.0",
    lifespan=lifespan
)


# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response


app.add_middleware(SecurityHeadersMiddleware)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if settings.CORS_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Register Routers
app.include_router(check_router)
app.include_router(stats_router)
app.include_router(blacklist_router)
app.include_router(alerts_router)
app.include_router(settings_router)
app.include_router(benchmark_router)

# Mount Static Files & Frontend
STATIC_DIR = Path(__file__).resolve().parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "Threat Intelligence API is running. Access documentation at /docs"}
