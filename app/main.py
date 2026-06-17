from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.config import get_settings
from app.core.rate_limit import limiter
from app.routers import (
    audit,
    auth,
    bom,
    buildings,
    confirmations,
    consult,
    contracts,
    customers,
    equipment,
    functional_locations,
    health,
    invoices,
    materials,
    meters,
    notifications,
    pm,
    portal,
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

    # CMMS v1 — PM engine (Phase 4)
    app.include_router(pm.router)

    # CMMS v1 — contracts, BOM, billing, customer portal (Phase 5)
    app.include_router(contracts.router)
    app.include_router(bom.router)
    app.include_router(invoices.router)
    app.include_router(portal.router)

    # Serve the built React SPA if `frontend/dist/` exists. The three surfaces
    # (/app, /tech, /portal) all resolve to the SPA's index.html so React
    # Router can take over client-side. Production deploys should run
    # `npm --prefix frontend run build` before starting the server.
    dist = Path("frontend/dist")
    if dist.is_dir():
        if (dist / "assets").is_dir():
            app.mount("/assets",
                      StaticFiles(directory=str(dist / "assets")),
                      name="spa-assets")

        index_html = str(dist / "index.html")

        def _spa() -> FileResponse:
            return FileResponse(index_html)

        for prefix in ("/app", "/tech", "/portal"):
            app.add_api_route(prefix, _spa, methods=["GET"], include_in_schema=False)
            app.add_api_route(
                f"{prefix}/{{rest:path}}", _spa,
                methods=["GET"], include_in_schema=False,
            )

    return app


app = create_app()
