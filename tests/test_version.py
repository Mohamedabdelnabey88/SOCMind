import tomllib
from pathlib import Path
from socmind import __version__
from socmind.cli import build_parser
from socmind.webapp import create_app


def test_version_matches_package_and_api(capsys):
    import pytest
    metadata = tomllib.loads(Path("pyproject.toml").read_text())
    assert __version__ == metadata["project"]["version"] == "1.6.0"
    assert create_app("examples/attack_chain.jsonl").version == __version__
    with pytest.raises(SystemExit) as result:
        build_parser().parse_args(["--version"])
    assert result.value.code == 0
    assert capsys.readouterr().out.strip() == f"SOCMind {__version__}"
