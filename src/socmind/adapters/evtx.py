from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

from .windows_xml import parse_windows_event_xml


def parse_evtx(path: str | Path):
    """Parse native .evtx files using the optional python-evtx dependency."""
    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:
        raise RuntimeError(
            "Native EVTX support requires the optional dependency. "
            "Install with: pip install 'socmind[evtx]'"
        ) from exc

    xml_events: list[str] = []
    with Evtx(str(path)) as log:
        for record in log.records():
            xml_events.append(record.xml())

    # Reuse the tested Windows XML normalizer instead of maintaining two parsers.
    with NamedTemporaryFile("w", suffix=".xml", encoding="utf-8", delete=False) as tmp:
        tmp.write("<Events>")
        tmp.write("\n".join(xml_events))
        tmp.write("</Events>")
        temp_path = tmp.name
    try:
        return parse_windows_event_xml(temp_path)
    finally:
        Path(temp_path).unlink(missing_ok=True)
