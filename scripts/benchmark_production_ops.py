"""Reproducible, bounded local benchmarks. Run from the repository root."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import statistics
import tempfile
import time

from fastapi.testclient import TestClient
from socmind.benchmark import run_benchmark
from socmind.command_center import add_case_note, case_detail, connect
from socmind.orchestration import orchestrate_alert_sqlite
from socmind.production_ops import AlertRecord
from socmind.webapp import create_app


def measure(operation):
    started, cpu = time.perf_counter(), time.process_time()
    value = operation()
    return value, {'wall_seconds': time.perf_counter()-started, 'cpu_seconds': time.process_time()-cpu}


def run():
    result = {'timestamp': datetime.now(timezone.utc).isoformat(), 'python': platform.python_version(),
              'platform': platform.platform(), 'limitations': ['Synthetic local data', 'SQLite only for queue/API measurements',
              'API measured in-process with TestClient, excludes network/TLS', 'No production scale guarantee'], 'events': [], 'cases': []}
    for count in (10000, 100000, 1000000):
        value, timing = measure(lambda: run_benchmark(count))
        result['events'].append({**asdict(value), **timing})
    with tempfile.TemporaryDirectory(prefix='socmind-load-') as temp:
        root = Path(temp)
        db = root / 'ops.db'
        now = datetime.now(timezone.utc)
        errors = []
        def ingest(index):
            try:
                alert = AlertRecord(f'LOAD-{index}', 'benchmark', now, 'Synthetic alert', 8,
                                    f'host-{index}', user=f'user-{index}', rule_id=f'rule-{index}')
                return orchestrate_alert_sqlite(db, alert, [], evidence_dir=root / 'evidence')
            except Exception as exc:
                errors.append(type(exc).__name__)
        previous = 0
        first = None
        for count in (100, 1000, 10000):
            started = time.perf_counter()
            for index in range(previous, count):
                item = ingest(index)
                if first is None and item is not None:
                    first = item
            elapsed = time.perf_counter()-started
            query_times=[]
            with connect(db) as conn:
                for _ in range(50):
                    start=time.perf_counter()
                    conn.execute('SELECT * FROM cases WHERE case_id=?', (first.case_id,)).fetchone()
                    query_times.append(time.perf_counter()-start)
                actual = conn.execute('SELECT COUNT(*) FROM cases').fetchone()[0]
            client=TestClient(create_app('examples/attack_chain.jsonl', command_db=db))
            latency=[]
            for _ in range(5):
                start=time.perf_counter(); response=client.get('/api/command-center'); latency.append(time.perf_counter()-start)
                if response.status_code != 200: errors.append(f'http-{response.status_code}')
            result['cases'].append({'target':count,'actual':actual,'new_cases':count-previous,
                                    'ingestion_seconds':elapsed,'new_cases_per_second':(count-previous)/elapsed,
                                    'point_query_median_ms':1000*statistics.median(query_times),
                                    'api_queue_median_ms':1000*statistics.median(latency),'cumulative_errors':len(errors)})
            previous=count
        # All workers replay exactly the same alert. No row or evidence multiplication.
        with ThreadPoolExecutor(max_workers=8) as pool:
            duplicate_results=list(pool.map(ingest,[0]*40))
            list(pool.map(lambda n:add_case_note(db,first.case_id,author=f'worker-{n}',text=f'Note {n}'),range(40)))
        detail=case_detail(db,first.case_id)
        result['concurrency']={'workers':8,'duplicate_attempts':40,
                               'duplicates_reported':sum(bool(x and x.duplicate) for x in duplicate_results),
                               'case_alerts':len(detail['alerts']),'notes':len(detail['notes']),'errors':errors}
    try:
        import resource
        result['process_peak_rss_kib']=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except ImportError:
        result['process_peak_rss_kib']=None
    return result

if __name__ == '__main__':
    print(json.dumps(run(),indent=2))
