"""Start an isolated firewall against a NEW SQLite synthetic dataset only."""

import json
import os
import re
from pathlib import Path

import uvicorn
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.base import Base
from app.main import create_app
from app.models.workflow import WorkflowBase
from app.services.agent_firewall import Firewall, Principal
from app.services.openai_provider import configured_provider
from scripts.seed_demo_data import seed_demo


def main():
    # No .env loading and no PostgreSQL connection. Secrets supplied out of band.
    root = Path(__file__).resolve().parents[2] / "tmp" / "agent-security"
    dataset = os.environ.get("FRAUDSENTINEL_FIREWALL_DATASET")
    if dataset:
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", dataset):
            raise ValueError("Invalid isolated dataset name")
        root = root / dataset
    if not root.resolve().is_relative_to(
        Path(__file__).resolve().parents[2] / "tmp"
    ) or root.resolve().is_relative_to(Path("F:/Fraud-Sentinel")):
        raise ValueError("Dataset must remain in the isolated snapshot")
    root.mkdir(parents=True, exist_ok=True)
    credentials = json.loads(os.environ["FRAUDSENTINEL_FIREWALL_CREDENTIALS"])
    identities = {
        entry["token"]: Principal(
            entry["id"], entry["kind"], entry["role"], entry["owner_id"], frozenset(entry["cases"])
        )
        for entry in credentials
    }
    key = bytes.fromhex(os.environ["FRAUDSENTINEL_FIREWALL_AUDIT_KEY"])
    engine = create_engine("sqlite:///" + (root / "synthetic.sqlite3").as_posix())
    if not (root / "synthetic.sqlite3").exists():
        Base.metadata.create_all(engine)
        WorkflowBase.metadata.create_all(engine)
        with Session(engine) as session, session.begin():
            seed_demo(session)
            if os.environ.get("FRAUDSENTINEL_FIREWALL_SEED_WORKFLOW") == "1":
                from scripts.seed_firewall_workflow import seed_firewall_workflow

                seed_firewall_workflow(session)
    if not set(WorkflowBase.metadata.tables) <= set(inspect(engine).get_table_names()):
        raise RuntimeError(
            "Existing dataset lacks workflow tables; choose a new isolated dataset, do not migrate"
        )
    firewall = Firewall(engine, root / "security.sqlite3", identities, key)
    config = Settings(_env_file=None, app_env="test", demo_mode=True, investigation_sandbox=True)
    application = create_app(config, engine, firewall=firewall, provider=configured_provider())
    uvicorn.run(
        application,
        host="127.0.0.1",
        port=int(os.environ.get("FRAUDSENTINEL_FIREWALL_PORT", "8002")),
        access_log=False,
    )


if __name__ == "__main__":
    main()
