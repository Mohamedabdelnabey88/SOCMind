from __future__ import annotations

from pathlib import Path

from .dashboard import build_dashboard_payload
from .io import load_jsonl


def create_app(events_path: str | Path, *, case_id: str = "SOCMIND-WEB"):
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
        version="0.7.0",
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.state.events_path = source
    app.state.case_id = case_id

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

    @app.get("/")
    def index():
        return FileResponse(assets / "index.html")

    app.mount("/assets", StaticFiles(directory=assets), name="assets")
    return app
