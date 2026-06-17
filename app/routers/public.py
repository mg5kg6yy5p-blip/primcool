from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter(tags=["public"])


@router.get("/")
def index() -> FileResponse:
    return FileResponse("index.html")
