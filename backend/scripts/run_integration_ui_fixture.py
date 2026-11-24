"""Test-only M1–M4 browser API: fresh SQLite, no PostgreSQL or migration commands."""

import argparse
import asyncio
from pathlib import Path

import uvicorn
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.config import Settings
from app.db.base import Base
from app.main import create_app
from app.models.workflow import WorkflowBase
from app.repositories.intelligence import IntelligenceRepository
from scripts.seed_demo_data import seed_demo
from scripts.synthetic_scenarios import create_scenarios


class SerializedTestApp:
    """StaticPool has one SQLite connection: serialize complete ASGI requests."""

    def __init__(self, app):
        self.app = app
        self.lock = asyncio.Lock()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            async with self.lock:
                await self.app(scope, receive, send)
        else:
            await self.app(scope, receive, send)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--investigations", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2] / "tmp" / "ui-regression"
    if not root.resolve().is_relative_to(
        Path(__file__).resolve().parents[2] / "tmp"
    ) or root.resolve().is_relative_to(Path("F:/Fraud-Sentinel")):
        raise RuntimeError("Only isolated snapshot test files are allowed")
    root.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    WorkflowBase.metadata.create_all(engine)
    with Session(engine) as session, session.begin():
        seed_demo(session)
        if args.investigations:
            create_scenarios(IntelligenceRepository(session, "user_demo_analyst"))
    config = Settings(
        _env_file=None,
        app_env="test",
        demo_mode=True,
        investigation_sandbox=args.investigations,
        cors_origins=["http://127.0.0.1:5178" if args.investigations else "http://127.0.0.1:5177"],
    )
    uvicorn.run(
        SerializedTestApp(create_app(config, engine)),
        host="127.0.0.1",
        port=8006 if args.investigations else 8005,
        access_log=False,
    )


if __name__ == "__main__":
    main()
