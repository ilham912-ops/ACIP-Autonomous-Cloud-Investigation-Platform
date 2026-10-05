"""
Endpoint FastAPI exposant les metriques du dashboard Security Manager.

A brancher sur l'application principale (main.py) via :
    from app.dashboard.router import router as dashboard_router
    app.include_router(dashboard_router, prefix="/api/dashboard", tags=["dashboard"])
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.dashboard.metrics import get_dashboard_summary

router = APIRouter()


@router.get("/summary")
def dashboard_summary(db: Session = Depends(get_db)):
    """Point d'entree unique pour le dashboard Security Manager -- MTTI,
    volume par type de donnee, taux de faux positifs, findings en attente."""
    return get_dashboard_summary(db)
