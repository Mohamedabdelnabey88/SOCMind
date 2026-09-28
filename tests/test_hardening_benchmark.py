import pytest

from socmind.benchmark import run_benchmark
from socmind.hardening import is_loopback_host, security_report, validate_web_binding


def test_remote_bind_requires_token_or_explicit_override():
    assert is_loopback_host("127.0.0.1")
    assert is_loopback_host("::1")

    with pytest.raises(ValueError):
        validate_web_binding("0.0.0.0", api_token=None)

    validate_web_binding("0.0.0.0", api_token="secret")
    validate_web_binding("0.0.0.0", api_token=None, allow_unsafe_remote=True)


def test_security_report_marks_loopback_safe():
    checks = {item.name: item for item in security_report(host="127.0.0.1")}
    assert checks["web-binding"].ok
    assert checks["api-token"].ok


def test_benchmark_runs_deterministically():
    result = run_benchmark(1000)
    assert result.events == 1000
    assert result.elapsed_seconds > 0
    assert result.events_per_second > 0
