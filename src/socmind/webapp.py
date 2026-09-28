from __future__ import annotations

from pathlib import Path

from .command_center import command_center_snapshot
from .dashboard import build_dashboard_payload
from .io import load_jsonl
from .lead_metrics import lead_snapshot


def create_app(events_path: str | Path, *, case_id: str = "SOCMIND-WEB", command_db: str | Path | None = None, rules_dir: str | Path = "detections", dispositions_path: str | Path | None = None):
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import FileResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:
        raise RuntimeError(
            "Web dashboard requires optional dependencies. Install with: pip install 'socmind[web]'"
        ) from exc

    source = Path(events_path).resolve()
    if not source.is_file():
        raise FileNotFoundError(source)

    assets = Path(__file__).with_name("web")
    app = FastAPI(
        title="SOCMind Web Investigation Dashboard",
        version="0.9.0",
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.state.events_path = source
    app.state.case_id = case_id
    app.state.command_db = Path(command_db).resolve() if command_db else None
    app.state.rules_dir = Path(rules_dir).resolve()
    app.state.dispositions_path = Path(dispositions_path).resolve() if dispositions_path else None

    @app.get("/health")
    def health():
        return {"status": "ok", "case_id": app.state.case_id}

    @app.get("/api/case")
    def case():
        try:
            events = load_jsonl(app.state.events_path)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return build_dashboard_payload(events, case_id=app.state.case_id)

    @app.get("/api/command-center")
    def command_center():
        if app.state.command_db is None:
            return {"enabled": False, "summary": {}, "queue": [], "workload": [], "sla_breaches": []}
        try:
            payload = command_center_snapshot(app.state.command_db)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {"enabled": True, **payload}

    @app.get("/api/lead-health")
    def lead_health():
        try:
            return lead_snapshot(
                app.state.events_path,
                rules_dir=app.state.rules_dir,
                dispositions_path=app.state.dispositions_path,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/")
    def index():
        return FileResponse(assets / "index.html")

    app.mount("/assets", StaticFiles(directory=assets), name="assets")
    return app
