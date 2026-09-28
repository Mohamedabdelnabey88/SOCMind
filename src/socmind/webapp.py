from pathlib import Path

from .audit_chain import append_record, verify_chain
from .command_center import (
    acknowledge_case,
    add_case_note,
    assign_case,
    case_detail,
    command_center_snapshot,
    get_case_quality,
    save_case_quality,
    transition_case,
)
from .contradiction import contradiction_payload
from .dashboard import build_dashboard_payload
from .detection_replay import detection_replay_payload
from .detections import load_rules
from .enterprise_auth import AuthConfig, authenticate
from .enterprise_command_center import (
    acknowledge_case_pg,
    add_case_note_pg,
    assign_case_pg,
    case_detail_pg,
    command_center_snapshot_pg,
    get_case_quality_pg,
    save_case_quality_pg,
    transition_case_pg,
)
from .io import load_jsonl
from .lead_metrics import lead_snapshot
from .quality_gate import load_checklist, quality_payload, review_investigation
from .rbac import Principal, require_permission
from .replay import replay_payload
from .rule_audit import rule_audit_payload
from .similarity import similarity_payload, similarity_payload_pg
from .whatif import compare_rule_packs


def create_app(
    events_path: str | Path,
    *,
    case_id: str = "SOCMIND-WEB",
    command_db: str | Path | None = None,
    rules_dir: str | Path = "detections",
    dispositions_path: str | Path | None = None,
    api_token: str | None = None,
    proposed_rules_dir: str | Path | None = None,
    quality_checklist_path: str | Path | None = None,
    auth_mode: str = "local-token",
    api_token_role: str = "admin",
    trusted_proxy_secret: str | None = None,
    enterprise_audit_path: str | Path | None = None,
    postgres_dsn: str | None = None,
    enforce_quality_on_close: bool = False,
):
    try:
        from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
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
        title="SOCMind Enterprise SOC Workspace",
        version="1.6.0",
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
    app.state.proposed_rules_dir = (
        Path(proposed_rules_dir).resolve() if proposed_rules_dir else None
    )
    app.state.quality_checklist_path = (
        Path(quality_checklist_path).resolve() if quality_checklist_path else None
    )
    app.state.enterprise_audit_path = (
        Path(enterprise_audit_path).resolve() if enterprise_audit_path else None
    )
    app.state.postgres_dsn = postgres_dsn
    app.state.enforce_quality_on_close = bool(enforce_quality_on_close)
    app.state.auth_config = AuthConfig(
        mode=auth_mode,
        api_token=api_token,
        api_token_role=api_token_role,
        trusted_proxy_secret=trusted_proxy_secret,
    )

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        return response

    def principal(request: Request) -> Principal:
        headers = {key.lower(): value for key, value in request.headers.items()}
        try:
            return authenticate(headers, app.state.auth_config)
        except (PermissionError, ValueError) as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def allowed(permission: str):
        def dependency(user: Principal = Depends(principal)) -> Principal:
            try:
                require_permission(user, permission)
            except PermissionError as exc:
                raise HTTPException(status_code=403, detail=str(exc)) from exc
            return user
        return dependency

    def require_store():
        if app.state.postgres_dsn:
            return ("postgres", app.state.postgres_dsn)
        if app.state.command_db is not None:
            return ("sqlite", app.state.command_db)
        raise HTTPException(
            status_code=409,
            detail="Command Center is not configured. Start with --command-db or --postgres-dsn.",
        )

    def store_snapshot(**kwargs):
        kind, target = require_store()
        if kind == "postgres":
            return command_center_snapshot_pg(target, **kwargs)
        return command_center_snapshot(target, **kwargs)

    def store_detail(case_id: str):
        kind, target = require_store()
        if kind == "postgres":
            return case_detail_pg(target, case_id)
        return case_detail(target, case_id)

    def store_ack(case_id: str, actor: str):
        kind, target = require_store()
        if kind == "postgres":
            return acknowledge_case_pg(target, case_id, actor=actor)
        return acknowledge_case(target, case_id, actor=actor)

    def store_assign(case_id: str, owner: str, actor: str):
        kind, target = require_store()
        if kind == "postgres":
            return assign_case_pg(target, case_id, owner, actor=actor)
        return assign_case(target, case_id, owner, actor=actor)

    def store_transition(case_id: str, target_state: str, actor: str):
        kind, target = require_store()
        if kind == "postgres":
            return transition_case_pg(target, case_id, target_state, actor=actor)
        return transition_case(target, case_id, target_state, actor=actor)

    def store_note(case_id: str, author: str, text: str, disposition):
        kind, target = require_store()
        if kind == "postgres":
            return add_case_note_pg(
                target,
                case_id,
                author=author,
                text=text,
                disposition=disposition,
            )
        return add_case_note(
            target,
            case_id,
            author=author,
            text=text,
            disposition=disposition,
        )


    def store_quality_get(case_id: str):
        kind, target = require_store()
        if kind == "postgres":
            return get_case_quality_pg(target, case_id)
        return get_case_quality(target, case_id)

    def store_quality_save(case_id: str, checklist: dict, actor: str):
        kind, target = require_store()
        if kind == "postgres":
            return save_case_quality_pg(
                target,
                case_id,
                checklist,
                actor=actor,
            )
        return save_case_quality(
            target,
            case_id,
            checklist,
            actor=actor,
        )

    def enterprise_audit(
        *,
        case_id: str,
        user: Principal,
        action: str,
        detail: str,
    ) -> None:
        if app.state.enterprise_audit_path is None:
            return
        append_record(
            app.state.enterprise_audit_path,
            case_id=case_id,
            actor=user.subject,
            action=action,
            detail=detail,
        )

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "case_id": app.state.case_id,
            "auth_mode": app.state.auth_config.mode,
            "auth_required": bool(app.state.auth_config.api_token)
            or app.state.auth_config.mode != "local-token",
            "command_center": app.state.command_db is not None or bool(app.state.postgres_dsn),
            "case_store": "postgres" if app.state.postgres_dsn else ("sqlite" if app.state.command_db is not None else "none"),
            "enterprise_audit": app.state.enterprise_audit_path is not None,
            "quality_close_enforced": app.state.enforce_quality_on_close,
        }

    @app.get("/api/me")
    def me(user: Principal = Depends(principal)):
        return {
            "subject": user.subject,
            "role": user.role,
            "source": user.source,
        }

    @app.get("/api/case")
    def case(user: Principal = Depends(allowed("case.read"))):
        try:
            events = load_jsonl(app.state.events_path)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return build_dashboard_payload(events, case_id=app.state.case_id)

    @app.get("/api/command-center")
    def command_center(
        q: str | None = Query(default=None, max_length=120),
        priority: str | None = Query(default=None, max_length=10),
        state: str | None = Query(default=None, max_length=40),
        owner: str | None = Query(default=None, max_length=120),
        limit: int = Query(default=25, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        user: Principal = Depends(allowed("case.read")),
    ):
        if app.state.command_db is None and not app.state.postgres_dsn:
            return {
                "enabled": False,
                "summary": {},
                "queue": [],
                "workload": [],
                "sla_breaches": [],
            }
        try:
            payload = store_snapshot(
                query=q,
                priority=priority,
                state=state,
                owner=owner,
                limit=limit,
                offset=offset,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {"enabled": True, **payload}

    @app.get("/api/cases/{target_case_id}")
    def case_record(
        target_case_id: str,
        user: Principal = Depends(allowed("case.read")),
    ):
        try:
            detail = store_detail(target_case_id)
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
        quality_record = store_quality_get(target_case_id)
        quality_review = None
        if evidence_path and Path(evidence_path).is_file():
            try:
                quality_review = quality_payload(
                    load_jsonl(evidence_path),
                    checklist=quality_record["checklist"],
                )
            except Exception as exc:
                quality_review = {"error": str(exc)}
        return {
            **detail,
            "investigation": investigation,
            "quality_checklist": quality_record,
            "quality_review": quality_review,
        }

    @app.post("/api/cases/{target_case_id}/acknowledge")
    def acknowledge(
        target_case_id: str,
        user: Principal = Depends(allowed("case.acknowledge")),
    ):
        try:
            store_ack(target_case_id, user.subject)
            enterprise_audit(
                case_id=target_case_id,
                user=user,
                action="case.acknowledge",
                detail="Case acknowledged",
            )
            return store_detail(target_case_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/cases/{target_case_id}/assign")
    def assign_endpoint(
        target_case_id: str,
        request: dict = Body(...),
        user: Principal = Depends(allowed("case.assign")),
    ):
        try:
            owner = str(request.get("owner", "")).strip()
            store_assign(target_case_id, owner, user.subject)
            enterprise_audit(
                case_id=target_case_id,
                user=user,
                action="case.assign",
                detail=f"Assigned to {owner}",
            )
            return store_detail(target_case_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/{target_case_id}/transition")
    def transition_endpoint(
        target_case_id: str,
        request: dict = Body(...),
        user: Principal = Depends(allowed("case.transition")),
    ):
        try:
            target = str(request.get("state", "")).strip()
            if target == "resolved" and app.state.enforce_quality_on_close:
                detail = store_detail(target_case_id)
                evidence_path = detail["case"].get("evidence_path")
                if not evidence_path or not Path(evidence_path).is_file():
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "message": "Case closure blocked: linked evidence is required.",
                            "blockers": ["Linked evidence unavailable"],
                        },
                    )
                quality_record = store_quality_get(target_case_id)
                review = review_investigation(
                    load_jsonl(evidence_path),
                    checklist=quality_record["checklist"],
                )
                if not review.closure_allowed:
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "message": "Case closure blocked by investigation quality gate.",
                            "readiness": review.readiness,
                            "blockers": review.blockers,
                            "warnings": review.warnings,
                        },
                    )
            store_transition(target_case_id, target, user.subject)
            enterprise_audit(
                case_id=target_case_id,
                user=user,
                action="case.transition",
                detail=f"Transitioned to {target}",
            )
            return store_detail(target_case_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/{target_case_id}/notes")
    def note_endpoint(
        target_case_id: str,
        request: dict = Body(...),
        user: Principal = Depends(allowed("case.note")),
    ):
        try:
            text = str(request.get("text", ""))
            note_id = store_note(
                target_case_id,
                user.subject,
                text,
                request.get("disposition"),
            )
            enterprise_audit(
                case_id=target_case_id,
                user=user,
                action="case.note",
                detail=text[:200],
            )
            return {"note_id": note_id, **store_detail(target_case_id)}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases/{target_case_id}/quality-checklist")
    def case_quality_checklist(
        target_case_id: str,
        user: Principal = Depends(allowed("case.read")),
    ):
        try:
            return store_quality_get(target_case_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.put("/api/cases/{target_case_id}/quality-checklist")
    def update_case_quality_checklist(
        target_case_id: str,
        request: dict = Body(...),
        user: Principal = Depends(allowed("case.quality")),
    ):
        try:
            raw = request.get("checklist")
            if not isinstance(raw, dict):
                raise ValueError("Body must contain a checklist object")
            record = store_quality_save(
                target_case_id,
                raw,
                user.subject,
            )
            enterprise_audit(
                case_id=target_case_id,
                user=user,
                action="case.quality",
                detail="Investigation quality checklist updated",
            )
            detail = store_detail(target_case_id)
            evidence_path = detail["case"].get("evidence_path")
            review = None
            if evidence_path and Path(evidence_path).is_file():
                review = quality_payload(
                    load_jsonl(evidence_path),
                    checklist=record["checklist"],
                )
            return {**record, "review": review}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/ire/replay")
    def ire_replay(user: Principal = Depends(allowed("reasoning.read"))):
        try:
            return replay_payload(load_jsonl(app.state.events_path))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/api/ire/detection-replay")
    def ire_detection_replay(
        user: Principal = Depends(allowed("reasoning.read")),
    ):
        try:
            events = load_jsonl(app.state.events_path)
            rules = load_rules(app.state.rules_dir)
            return detection_replay_payload(events, rules)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/api/ire/what-if")
    def ire_what_if(user: Principal = Depends(allowed("detection.review"))):
        if app.state.proposed_rules_dir is None:
            return {"enabled": False}
        try:
            events = load_jsonl(app.state.events_path)
            current = load_rules(app.state.rules_dir)
            proposed = load_rules(app.state.proposed_rules_dir)
            result = compare_rule_packs(events, current, proposed)
            return {
                "enabled": True,
                "current": result.current,
                "proposed": result.proposed,
                "first_detection_step_improvement": result.first_detection_step_improvement,
                "visibility_delta": result.visibility_delta,
                "blind_step_delta": result.blind_step_delta,
                "newly_covered_techniques": result.newly_covered_techniques,
            }
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/api/ire/quality")
    def ire_quality(user: Principal = Depends(allowed("reasoning.read"))):
        try:
            checklist = load_checklist(app.state.quality_checklist_path)
            return quality_payload(
                load_jsonl(app.state.events_path),
                checklist=checklist,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/api/reasoning/contradictions")
    def reasoning_contradictions(
        user: Principal = Depends(allowed("reasoning.read")),
    ):
        try:
            return contradiction_payload(load_jsonl(app.state.events_path))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/api/reasoning/similar")
    def reasoning_similar(
        limit: int = Query(default=5, ge=1, le=20),
        min_score: float = Query(default=15.0, ge=0.0, le=100.0),
        user: Principal = Depends(allowed("reasoning.read")),
    ):
        if app.state.command_db is None and not app.state.postgres_dsn:
            return {
                "enabled": False,
                "matches": [],
                "summary": {"matches": 0, "highest_score": 0.0},
                "interpretation": (
                    "Similarity requires a configured command-center store "
                    "containing evidence-linked historical cases."
                ),
            }
        try:
            if app.state.postgres_dsn:
                payload = similarity_payload_pg(
                    load_jsonl(app.state.events_path),
                    app.state.postgres_dsn,
                    limit=limit,
                    min_score=min_score,
                    exclude_case_id=app.state.case_id,
                )
            else:
                payload = similarity_payload(
                    load_jsonl(app.state.events_path),
                    app.state.command_db,
                    limit=limit,
                    min_score=min_score,
                    exclude_case_id=app.state.case_id,
                )
            return {"enabled": True, **payload}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/api/detections/audit")
    def detections_audit(user: Principal = Depends(allowed("lead.read"))):
        try:
            return rule_audit_payload(app.state.rules_dir)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/api/lead-health")
    def lead_health(user: Principal = Depends(allowed("lead.read"))):
        try:
            return lead_snapshot(
                app.state.events_path,
                rules_dir=app.state.rules_dir,
                dispositions_path=app.state.dispositions_path,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/api/enterprise/audit/verify")
    def audit_verify(user: Principal = Depends(allowed("audit.read"))):
        if app.state.enterprise_audit_path is None:
            return {"enabled": False, "valid": True, "records": 0}
        valid, records, error = verify_chain(app.state.enterprise_audit_path)
        return {
            "enabled": True,
            "valid": valid,
            "records": records,
            "error": error,
        }

    @app.get("/")
    def index():
        return FileResponse(assets / "index.html")

    app.mount("/assets", StaticFiles(directory=assets), name="assets")
    return app
