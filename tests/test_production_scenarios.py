"""Synthetic full-workflow scenarios; containment and closure are analyst actions."""
import json
from pathlib import Path
import pytest

from socmind.adapters.wazuh import wazuh_alert_to_event
from socmind.adapters.elastic import parse_elastic_hit
from socmind.command_center import (acknowledge_case, add_case_note, assign_case, case_detail,
                                    record_case_activity, transition_case)
from socmind.contradiction import review_hypotheses
from socmind.dashboard import build_dashboard_payload
from socmind.engine import analyze
from socmind.evidence_artifacts import register_artifact, verify_artifacts
from socmind.evidence_storage import LocalEvidenceStore
from socmind.evidence_requests import ensure_suggested_requirements_sqlite
from socmind.io import load_jsonl
from socmind.orchestration import orchestrate_alert_sqlite
from socmind.production_ops import alert_from_event
from socmind.quality_gate import review_investigation
from socmind.rbac import Principal
from socmind.unified_timeline import build_unified_case_timeline

ROOT = Path(__file__).resolve().parents[1] / 'examples/production-scenarios'
SCENARIOS = json.loads((ROOT / 'manifest.json').read_text())


@pytest.mark.parametrize('scenario', SCENARIOS, ids=lambda s:s['name'])
def test_full_analyst_workflow(scenario, tmp_path):
    events = load_jsonl(ROOT / scenario['events'])
    raws = [json.loads(x) for x in (ROOT / scenario['alerts']).read_text().splitlines()]
    parse = wazuh_alert_to_event if scenario['provider']=='wazuh' else parse_elastic_hit
    alerts = [alert_from_event(parse(raw)) for raw in raws]
    db=tmp_path/'scenario.db'
    results=[orchestrate_alert_sqlite(db, a, events, evidence_dir=tmp_path/'working') for a in alerts]
    assert results[0].created and not results[1].created
    assert results[0].case_id == results[1].case_id
    case_id=results[0].case_id
    duplicate=orchestrate_alert_sqlite(db,alerts[1],events,evidence_dir=tmp_path/'working')
    assert duplicate.duplicate
    findings=analyze(events)
    assert bool(findings) == scenario['expected_findings']
    if findings:
        assert any(f.techniques for f in findings)
    reviews=review_hypotheses(events)
    quality=review_investigation(events)
    assert quality.total > 0  # Outstanding items remain visible, not auto-completed.
    acknowledge_case(db,case_id,actor='scenario-t1')
    assign_case(db,case_id,'scenario-t2',actor='scenario-lead')
    transition_case(db,case_id,'triage',actor='scenario-t2',reason='Initial review')
    transition_case(db,case_id,'investigating',actor='scenario-t2',reason='Review telemetry')
    add_case_note(db,case_id,author='scenario-t2',text=f'Reviewed {len(reviews)} hypotheses; outstanding quality items: {quality.outstanding}')
    ensure_suggested_requirements_sqlite(db,case_id=case_id,events=events,requested_by='scenario-t2')
    record_case_activity(db,case_id,activity='escalation',actor='scenario-t2',detail='Analyst review requested; synthetic exercise')
    store=LocalEvidenceStore(tmp_path/'objects')
    actor=Principal('scenario-t2','senior-analyst','test')
    register_artifact(db,case_id,ROOT/scenario['events'],store,storage_id='local',source=scenario['provider'],principal=actor)
    assert verify_artifacts(db,case_id,{'local':store},principal=actor)[0]['integrity_status']=='verified'
    transition_case(db,case_id,scenario['analyst_disposition'],actor='scenario-t2',reason='Exercise disposition after analyst review; gaps retained')
    record_case_activity(db,case_id,activity='detection-feedback',actor='scenario-t2',detail='Synthetic scenario feedback: '+scenario['analyst_disposition'])
    detail=case_detail(db,case_id)
    assert len(detail['alerts'])==2
    assert detail['alerts'][1]['correlation_reasons']
    timeline=build_unified_case_timeline(detail,build_dashboard_payload(events,case_id=case_id))
    types={e['type'] for e in timeline}
    assert {'case-created','alert-correlated','evidence-event','assignment','note','escalation','detection-feedback'} <= types
