import secrets
from datetime import datetime
from pathlib import Path

from .audit_chain import append_record, verify_chain
from .command_center import (
    acknowledge_case,
    add_case_note,
    assign_case,
    case_detail,
    command_center_snapshot,
    record_case_activity,
    transition_case,
)
from .contradiction import contradiction_payload
from .dashboard import build_dashboard_payload
from .detection_replay import detection_replay_payload
from .detections import load_rules
from .enterprise_auth import AuthConfig, authenticate
from .oidc_auth import (
    OIDCConfig,
    build_authorization_url,
    decode_signed_payload,
    exchange_code,
    fetch_discovery,
    new_authorization_transaction,
    parse_role_map,
    session_from_claims,
    validate_oidc_config,
    verify_id_token,
)
from .evidence_integrity import evidence_manifest_path, verification_payload, verify_evidence_manifest
from .evidence_requests import (
    create_requirement_pg,
    create_requirement_sqlite,
    ensure_suggested_requirements_pg,
    ensure_suggested_requirements_sqlite,
    suggestion_payload,
    update_requirement_pg,
    update_requirement_sqlite,
)
from .enterprise_command_center import (
    acknowledge_case_pg,
    add_case_note_pg,
    assign_case_pg,
    case_detail_pg,
    command_center_snapshot_pg,
    record_case_activity_pg,
    transition_case_pg,
)
from .io import load_jsonl
from .lead_metrics import lead_snapshot
from .quality_gate import load_checklist, quality_payload
from .rbac import Principal, require_permission
from .replay import replay_payload
from .similarity import similarity_payload, similarity_payload_pg
from .whatif import compare_rule_packs
from .unified_timeline import build_unified_case_timeline



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
    oidc_issuer: str | None = None,
    oidc_client_id: str | None = None,
    oidc_client_secret: str | None = None,
    oidc_redirect_uri: str | None = None,
    oidc_session_secret: str | None = None,
    oidc_role_claim: str = "groups",
    oidc_role_map: dict[str, str] | str | None = None,
    oidc_default_role: str = "viewer",
    oidc_scopes: str = "openid profile email",
    oidc_allow_insecure_http: bool = False,
    enterprise_audit_path: str | Path | None = None,
    postgres_dsn: str | None = None,
):
    try:
        from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
        from fastapi.responses import FileResponse, RedirectResponse
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
    app.state.oidc_config = None
    if auth_mode.strip().lower() == "oidc":
        app.state.oidc_config = validate_oidc_config(OIDCConfig(
            issuer=str(oidc_issuer or ""),
            client_id=str(oidc_client_id or ""),
            client_secret=oidc_client_secret,
            redirect_uri=str(oidc_redirect_uri or ""),
            session_secret=str(oidc_session_secret or ""),
            role_claim=str(oidc_role_claim or "groups"),
            role_map=parse_role_map(oidc_role_map),
            default_role=str(oidc_default_role or "viewer"),
            scopes=str(oidc_scopes or "openid profile email"),
            allow_insecure_http=bool(oidc_allow_insecure_http),
        ))

    app.state.auth_config = AuthConfig(
        mode=auth_mode,
        api_token=api_token,
        api_token_role=api_token_role,
        trusted_proxy_secret=trusted_proxy_secret,
        oidc_session_secret=(
            app.state.oidc_config.session_secret
            if app.state.oidc_config is not None
            else None
        ),
        oidc_session_cookie=(
            app.state.oidc_config.session_cookie
            if app.state.oidc_config is not None
            else "socmind_oidc_session"
        ),
        oidc_issuer=(
            app.state.oidc_config.issuer
            if app.state.oidc_config is not None
            else None
        ),
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

    def evidence_integrity_for_detail(detail: dict) -> dict:
        evidence_value = (detail.get("case") or {}).get("evidence_path")
        if not evidence_value:
            return {"available": False, "valid": None, "reason": "no-evidence"}
        evidence_path = Path(evidence_value)
        if not evidence_path.is_file():
            return {
                "available": False,
                "valid": False,
                "reason": "evidence-missing",
                "evidence_path": str(evidence_path),
            }
        manifest_path = evidence_manifest_path(evidence_path)
        if not manifest_path.is_file():
            return {
                "available": False,
                "valid": None,
                "reason": "manifest-missing",
                "evidence_path": str(evidence_path),
                "manifest_path": str(manifest_path),
            }
        try:
            result = verify_evidence_manifest(evidence_path, manifest_path)
        except (OSError, ValueError, TypeError) as exc:
            return {
                "available": True,
                "valid": False,
                "reason": "verification-error",
                "error": str(exc),
                "evidence_path": str(evidence_path),
                "manifest_path": str(manifest_path),
            }
        return {"available": True, **verification_payload(result)}

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

    def store_transition(
        case_id: str,
        target_state: str,
        actor: str,
        reason: str | None = None,
    ):
        kind, target = require_store()
        if kind == "postgres":
            return transition_case_pg(
                target,
                case_id,
                target_state,
                actor=actor,
                reason=reason,
            )
        return transition_case(
            target,
            case_id,
            target_state,
            actor=actor,
            reason=reason,
        )

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

    def store_activity(case_id: str, activity: str, actor: str, detail: str):
        kind, target = require_store()
        if kind == "postgres":
            return record_case_activity_pg(
                target,
                case_id,
                activity=activity,
                actor=actor,
                detail=detail,
            )
        return record_case_activity(
            target,
            case_id,
            activity=activity,
            actor=actor,
            detail=detail,
        )

    def case_events_for_requirements(case_id: str):
        detail = store_detail(case_id)
        evidence_value = (detail.get("case") or {}).get("evidence_path")
        if evidence_value and Path(evidence_value).is_file():
            return load_jsonl(evidence_value)
        if case_id == app.state.case_id:
            return load_jsonl(app.state.events_path)
        return []

    def store_create_requirement(case_id: str, request: dict, actor: str):
        kind, target = require_store()
        kwargs = {
            "case_id": case_id,
            "key": request.get("key"),
            "title": request.get("title"),
            "source": request.get("source"),
            "target": request.get("target"),
            "rationale": request.get("rationale"),
            "requested_by": actor,
            "assigned_to": request.get("assigned_to"),
            "due_hours": request.get("due_hours", 4),
        }
        if kind == "postgres":
            return create_requirement_pg(target, **kwargs)
        return create_requirement_sqlite(target, **kwargs)

    def store_generate_requirements(
        case_id: str,
        actor: str,
        *,
        assigned_to=None,
        due_hours=4,
    ):
        events = case_events_for_requirements(case_id)
        if not events:
            raise ValueError(
                "No case evidence is available to derive evidence requirements"
            )
        kind, target = require_store()
        kwargs = {
            "case_id": case_id,
            "events": events,
            "requested_by": actor,
            "assigned_to": assigned_to,
            "due_hours": due_hours,
        }
        if kind == "postgres":
            return ensure_suggested_requirements_pg(target, **kwargs)
        return ensure_suggested_requirements_sqlite(target, **kwargs)

    def store_update_requirement(requirement_id: str, request: dict, actor: str):
        kind, target = require_store()
        kwargs = {
            "status": request.get("status"),
            "actor": actor,
            "response_summary": request.get("response_summary"),
            "evidence_reference": request.get("evidence_reference"),
            "assigned_to": request.get("assigned_to"),
        }
        if kind == "postgres":
            return update_requirement_pg(target, requirement_id, **kwargs)
        return update_requirement_sqlite(target, requirement_id, **kwargs)

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

    @app.get("/auth/login")
    def oidc_login(return_to: str = Query(default="/", max_length=500)):
        config = app.state.oidc_config
        if config is None:
            raise HTTPException(status_code=404, detail="OIDC authentication is not enabled")
        try:
            discovery = fetch_discovery(config)
            transaction_cookie, challenge = new_authorization_transaction(
                config,
                return_to=return_to,
            )
            target = build_authorization_url(
                config,
                discovery,
                transaction_cookie,
                challenge,
            )
        except (OSError, ValueError, PermissionError) as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        response = RedirectResponse(target, status_code=302)
        response.set_cookie(
            config.transaction_cookie,
            transaction_cookie,
            max_age=600,
            httponly=True,
            secure=not config.allow_insecure_http,
            samesite="lax",
            path="/auth",
        )
        return response

    @app.get("/auth/callback")
    def oidc_callback(
        request: Request,
        code: str | None = Query(default=None, max_length=4096),
        state: str | None = Query(default=None, max_length=512),
        error: str | None = Query(default=None, max_length=256),
        error_description: str | None = Query(default=None, max_length=1000),
    ):
        config = app.state.oidc_config
        if config is None:
            raise HTTPException(status_code=404, detail="OIDC authentication is not enabled")
        if error:
            raise HTTPException(
                status_code=401,
                detail=f"OIDC authorization failed: {error}: {error_description or ''}".strip(),
            )
        if not code or not state:
            raise HTTPException(status_code=400, detail="OIDC callback is missing code or state")
        transaction_cookie = request.cookies.get(config.transaction_cookie)
        if not transaction_cookie:
            raise HTTPException(status_code=400, detail="OIDC transaction cookie is missing")
        try:
            transaction = decode_signed_payload(
                transaction_cookie,
                config.session_secret,
            )
            if not secrets.compare_digest(
                str(transaction.get("state") or ""),
                str(state),
            ):
                raise PermissionError("OIDC state validation failed")
            discovery = fetch_discovery(config)
            tokens = exchange_code(
                config,
                discovery,
                code=code,
                verifier=str(transaction["verifier"]),
            )
            claims = verify_id_token(
                config,
                discovery,
                str(tokens["id_token"]),
                nonce=str(transaction["nonce"]),
            )
            session_cookie, session = session_from_claims(config, claims)
        except (OSError, ValueError, PermissionError, RuntimeError, KeyError) as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

        target = str(transaction.get("return_to") or "/")
        if not target.startswith("/"):
            target = "/"
        response = RedirectResponse(target, status_code=303)
        response.delete_cookie(config.transaction_cookie, path="/auth")
        response.set_cookie(
            config.session_cookie,
            session_cookie,
            max_age=max(60, int(session["exp"]) - int(datetime.now().timestamp())),
            httponly=True,
            secure=not config.allow_insecure_http,
            samesite="lax",
            path="/",
        )
        return response

    @app.post("/auth/logout")
    def oidc_logout():
        config = app.state.oidc_config
        response = RedirectResponse("/", status_code=303)
        if config is not None:
            response.delete_cookie(config.session_cookie, path="/")
            response.delete_cookie(config.transaction_cookie, path="/auth")
        return response

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
        return {
            **detail,
            "investigation": investigation,
            "evidence_integrity": evidence_integrity_for_detail(detail),
            "case_timeline": build_unified_case_timeline(detail, investigation),
        }

    @app.get("/api/cases/{target_case_id}/timeline")
    def case_timeline_endpoint(
        target_case_id: str,
        user: Principal = Depends(allowed("case.read")),
    ):
        try:
            detail = store_detail(target_case_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        investigation = None
        evidence_path = (detail.get("case") or {}).get("evidence_path")
        if evidence_path and Path(evidence_path).is_file():
            try:
                investigation = build_dashboard_payload(
                    load_jsonl(evidence_path),
                    case_id=target_case_id,
                )
            except Exception as exc:
                investigation = {"error": str(exc)}
        return {
            "case_id": target_case_id,
            "timeline": build_unified_case_timeline(detail, investigation),
        }

    @app.get("/api/cases/{target_case_id}/evidence-integrity")
    def case_evidence_integrity(
        target_case_id: str,
        user: Principal = Depends(allowed("case.read")),
    ):
        try:
            detail = store_detail(target_case_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return evidence_integrity_for_detail(detail)

    @app.get("/api/cases/{target_case_id}/evidence-requirements/suggestions")
    def evidence_requirement_suggestions(
        target_case_id: str,
        user: Principal = Depends(allowed("evidence.read")),
    ):
        try:
            store_detail(target_case_id)
            return suggestion_payload(
                case_events_for_requirements(target_case_id)
            )
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.post("/api/cases/{target_case_id}/evidence-requirements")
    def create_evidence_requirement(
        target_case_id: str,
        request: dict = Body(...),
        user: Principal = Depends(allowed("evidence.request")),
    ):
        try:
            requirement_id = store_create_requirement(
                target_case_id,
                request,
                user.subject,
            )
            enterprise_audit(
                case_id=target_case_id,
                user=user,
                action="evidence.requirement.create",
                detail=f"Evidence requirement {requirement_id}",
            )
            return {
                "requirement_id": requirement_id,
                **store_detail(target_case_id),
            }
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/{target_case_id}/evidence-requirements/generate")
    def generate_evidence_requirements(
        target_case_id: str,
        request: dict = Body(default={}),
        user: Principal = Depends(allowed("evidence.request")),
    ):
        try:
            requirement_ids = store_generate_requirements(
                target_case_id,
                user.subject,
                assigned_to=request.get("assigned_to"),
                due_hours=request.get("due_hours", 4),
            )
            enterprise_audit(
                case_id=target_case_id,
                user=user,
                action="evidence.requirement.generate",
                detail=f"Generated/resolved {len(requirement_ids)} requirement(s)",
            )
            return {
                "requirement_ids": requirement_ids,
                **store_detail(target_case_id),
            }
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/evidence-requirements/{requirement_id}")
    def update_evidence_requirement(
        requirement_id: str,
        request: dict = Body(...),
        user: Principal = Depends(principal),
    ):
        target_status = str(request.get("status", "")).strip().lower()
        permission = (
            "evidence.waive"
            if target_status == "waived"
            else "evidence.request"
            if target_status == "requested"
            else "evidence.manage"
        )
        try:
            require_permission(user, permission)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

        try:
            case_id = store_update_requirement(
                requirement_id,
                request,
                user.subject,
            )
            enterprise_audit(
                case_id=case_id,
                user=user,
                action="evidence.requirement.update",
                detail=f"{requirement_id} -> {target_status}",
            )
            return store_detail(case_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/{target_case_id}/activities")
    def case_activity_endpoint(
        target_case_id: str,
        request: dict = Body(...),
        user: Principal = Depends(principal),
    ):
        activity = str(request.get("type", "")).strip().lower()
        permission = (
            "detection.review"
            if activity == "detection-feedback"
            else "case.transition"
        )
        try:
            require_permission(user, permission)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

        try:
            detail = str(request.get("detail", "")).strip()
            store_activity(
                target_case_id,
                activity,
                user.subject,
                detail,
            )
            enterprise_audit(
                case_id=target_case_id,
                user=user,
                action=f"case.activity.{activity}",
                detail=detail,
            )
            return store_detail(target_case_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

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
            reason = str(request.get("reason", "")).strip()
            store_transition(
                target_case_id,
                target,
                user.subject,
                reason=reason,
            )
            audit_detail = f"Transitioned to {target}"
            if reason:
                audit_detail += f" | reason: {reason}"
            enterprise_audit(
                case_id=target_case_id,
                user=user,
                action="case.transition",
                detail=audit_detail,
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
                    exclude_case_id=app.state.case_id,
                )
            else:
                payload = similarity_payload(
                    load_jsonl(app.state.events_path),
                    app.state.command_db,
                    limit=limit,
                    exclude_case_id=app.state.case_id,
                )
            return {"enabled": True, **payload}
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
    def index(request: Request):
        if app.state.auth_config.mode.strip().lower() == "oidc":
            try:
                headers = {key.lower(): value for key, value in request.headers.items()}
                authenticate(headers, app.state.auth_config)
            except (PermissionError, ValueError):
                return RedirectResponse("/auth/login?return_to=/", status_code=302)
        return FileResponse(assets / "index.html")

    app.mount("/assets", StaticFiles(directory=assets), name="assets")
    return app
