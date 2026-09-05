from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "RSTR SENTINEL API",
        "message": "Backend security system is running"
    }