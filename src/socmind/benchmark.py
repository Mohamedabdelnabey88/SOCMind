from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from time import perf_counter

from .engine import analyze
from .models import Event


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    events: int
    findings: int
    elapsed_seconds: float
    events_per_second: float


def synthetic_events(count: int) -> list[Event]:
    count = max(1, int(count))
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events: list[Event] = []
    for idx in range(count):
        event_id = "4625" if idx % 100 == 0 else "4624"
        events.append(
            Event(
                timestamp=start + timedelta(seconds=idx),
                source="benchmark",
                event_id=event_id,
                host=f"HOST-{idx % 50:02d}",
                user=f"user-{idx % 100:03d}",
                src_ip=f"198.51.100.{(idx % 200) + 1}",
                process="powershell.exe" if idx % 250 == 0 else None,
                command_line="powershell.exe -nop -w hidden" if idx % 250 == 0 else None,
            )
        )
    return events


def run_benchmark(count: int = 5000) -> BenchmarkResult:
    events = synthetic_events(count)
    start = perf_counter()
    findings = analyze(events)
    elapsed = max(perf_counter() - start, 1e-9)
    return BenchmarkResult(
        events=len(events),
        findings=len(findings),
        elapsed_seconds=round(elapsed, 6),
        events_per_second=round(len(events) / elapsed, 1),
    )


def benchmark_payload(count: int = 5000) -> dict:
    return asdict(run_benchmark(count))
