from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@router.get("/readyz")
def readyz() -> dict:
    # Extended later to ping DB/redis; kept trivial for the skeleton.
    return {"status": "ready"}
