from __future__ import annotations

import secrets
from pathlib import Path

from .command_center import (
    acknowledge_case,
    add_case_note,
    assign_case,
    case_detail,
    command_center_snapshot,
    transition_case,
)
from .dashboard import build_dashboard_payload
from .io import load_jsonl
from .lead_metrics import lead_snapshot


def create_app(
    events_path: str | Path,
    *,
    case_id: str = "SOCMIND-WEB",
    command_db: str | Path | None = None,
    rules_dir: str | Path = "detections",
    dispositions_path: str | Path | None = None,
    api_token: str | None = None,
):
    try:
        from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query
        from fastapi.responses import FileResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:
        raise RuntimeError(
            "Web dashboard requires optional dependencies. "
            "Install with: pip install 'socmind[web]'"
        ) from exc

    source = Path(events_path).resolve()
    if not source.is_file():
        raise FileNotFoundError(source)

    assets = Path(__file__).with_name("web")
    app = FastAPI(
        title="SOCMind Real SOC Workspace",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.state.events_path = source
    app.state.case_id = case_id
    app.state.command_db = Path(command_db).resolve() if command_db else None
    app.state.rules_dir = Path(rules_dir).resolve()
    app.state.dispositions_path = (
        Path(dispositions_path).resolve() if dispositions_path else None
    )
    app.state.api_token = api_token

    def require_token(x_socmind_token: str | None = Header(default=None)) -> None:
        expected = app.state.api_token
        if not expected:
            return
        if not x_socmind_token or not secrets.compare_digest(x_socmind_token, expected):
            raise HTTPException(status_code=401, detail="Invalid SOCMind API token")

    def require_db() -> Path:
        if app.state.command_db is None:
            raise HTTPException(
                status_code=409,
                detail="Command Center is not configured. Start with --command-db.",
            )
        return app.state.command_db

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "case_id": app.state.case_id,
            "auth_required": bool(app.state.api_token),
            "command_center": app.state.command_db is not None,
        }

    @app.get("/api/case", dependencies=[Depends(require_token)])
    def case():
        try:
            events = load_jsonl(app.state.events_path)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return build_dashboard_payload(events, case_id=app.state.case_id)

    @app.get("/api/command-center", dependencies=[Depends(require_token)])
    def command_center(
        q: str | None = Query(default=None, max_length=120),
        priority: str | None = Query(default=None, max_length=10),
        state: str | None = Query(default=None, max_length=40),
        owner: str | None = Query(default=None, max_length=120),
    ):
        if app.state.command_db is None:
            return {
                "enabled": False,
                "summary": {},
                "queue": [],
                "workload": [],
                "sla_breaches": [],
            }
        try:
            payload = command_center_snapshot(
                app.state.command_db,
                query=q,
                priority=priority,
                state=state,
                owner=owner,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {"enabled": True, **payload}

    @app.get("/api/cases/{target_case_id}", dependencies=[Depends(require_token)])
    def case_record(target_case_id: str):
        db = require_db()
        try:
            detail = case_detail(db, target_case_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        evidence_path = detail["case"].get("evidence_path")
        investigation = None
        if evidence_path and Path(evidence_path).is_file():
            try:
                investigation = build_dashboard_payload(
                    load_jsonl(evidence_path),
                    case_id=target_case_id,
                )
            except Exception as exc:
                investigation = {"error": str(exc)}
        return {**detail, "investigation": investigation}

    @app.post(
        "/api/cases/{target_case_id}/acknowledge",
        dependencies=[Depends(require_token)],
    )
    def acknowledge(target_case_id: str, actor: str = "web-analyst"):
        db = require_db()
        try:
            acknowledge_case(db, target_case_id, actor=actor)
            return case_detail(db, target_case_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post(
        "/api/cases/{target_case_id}/assign",
        dependencies=[Depends(require_token)],
    )
    def assign_endpoint(target_case_id: str, request: dict = Body(...)):
        db = require_db()
        try:
            assign_case(
                db,
                target_case_id,
                str(request.get("owner", "")).strip(),
                actor=str(request.get("actor", "web-analyst")),
            )
            return case_detail(db, target_case_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post(
        "/api/cases/{target_case_id}/transition",
        dependencies=[Depends(require_token)],
    )
    def transition_endpoint(target_case_id: str, request: dict = Body(...)):
        db = require_db()
        try:
            transition_case(
                db,
                target_case_id,
                str(request.get("state", "")).strip(),
                actor=str(request.get("actor", "web-analyst")),
            )
            return case_detail(db, target_case_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post(
        "/api/cases/{target_case_id}/notes",
        dependencies=[Depends(require_token)],
    )
    def note_endpoint(target_case_id: str, request: dict = Body(...)):
        db = require_db()
        try:
            note_id = add_case_note(
                db,
                target_case_id,
                author=str(request.get("author", "web-analyst")),
                text=str(request.get("text", "")),
                disposition=request.get("disposition"),
            )
            return {"note_id": note_id, **case_detail(db, target_case_id)}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/lead-health", dependencies=[Depends(require_token)])
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
