from socmind.doctor import run_doctor
from socmind.helptext import render_help


def test_help_topics_are_actionable():
    text = render_help("integrations")
    assert "WAZUH_API_USER" in text
    assert "elastic-pull" in text
    assert "misp-enrich" in text

    overview = render_help()
    assert "getting-started" in overview
    assert "socmind doctor" in overview


def test_doctor_reports_python_and_platform():
    checks = {item.name: item for item in run_doctor()}
    assert checks["python"].ok
    assert checks["platform"].detail
