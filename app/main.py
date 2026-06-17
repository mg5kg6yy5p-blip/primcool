from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.config import get_settings
from app.core.rate_limit import limiter
from app.routers import (
    audit,
    auth,
    buildings,
    confirmations,
    consult,
    customers,
    equipment,
    functional_locations,
    health,
    materials,
    meters,
    notifications,
    public,
    saved_views,
    sites,
    spaces,
    users,
    work_orders,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="PrimeCool", lifespan=lifespan)

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origin_list(),
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    app.mount("/images", StaticFiles(directory="images"), name="images")

    app.include_router(health.router)
    app.include_router(public.router)
    app.include_router(consult.router)

    # Auth (argon2id + JWT + 4 roles)
    app.include_router(auth.router)
    app.include_router(users.router)

    # CMMS v1 — hierarchy & assets (Phase 1)
    app.include_router(customers.router)
    app.include_router(sites.router)
    app.include_router(buildings.router)
    app.include_router(spaces.router)
    app.include_router(functional_locations.router)
    app.include_router(equipment.router)
    app.include_router(meters.router)
    app.include_router(audit.router)

    # CMMS v1 — notification -> triage -> order (Phase 2)
    app.include_router(notifications.router)
    app.include_router(work_orders.router)
    app.include_router(saved_views.router)

    # CMMS v1 — confirmations & inventory (Phase 3)
    app.include_router(materials.router)
    app.include_router(confirmations.router)

    return app


app = create_app()
