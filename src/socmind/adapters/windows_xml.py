from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from ..models import Event

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _text(node, path: str, default: str = "") -> str:
    child = node.find(path, NS)
    return child.text if child is not None and child.text is not None else default


def parse_windows_event_xml(path: str | Path) -> list[Event]:
    """Parse Windows Event Viewer XML exports containing one or more Event nodes."""
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    # Event Viewer may export a single Event or a wrapped Events collection.
    try:
        root = ET.fromstring(raw)
        nodes = [root] if root.tag.endswith("Event") else list(root.findall(".//e:Event", NS))
    except ET.ParseError:
        wrapped = f"<Events>{raw}</Events>"
        root = ET.fromstring(wrapped)
        nodes = list(root)

    events: list[Event] = []
    for node in nodes:
        system = node.find("e:System", NS)
        if system is None:
            continue
        event_id = _text(system, "e:EventID")
        computer = _text(system, "e:Computer", "windows-host")
        time_node = system.find("e:TimeCreated", NS)
        system_time = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
        if not system_time:
            continue
        timestamp = datetime.fromisoformat(system_time.replace("Z", "+00:00"))

        data_map: dict[str, str] = {}
        event_data = node.find("e:EventData", NS)
        if event_data is not None:
            for item in event_data.findall("e:Data", NS):
                name = item.attrib.get("Name")
                if name:
                    data_map[name] = item.text or ""

        events.append(Event(
            timestamp=timestamp,
            source="windows-event-xml",
            event_id=event_id,
            host=computer,
            user=data_map.get("TargetUserName") or data_map.get("SubjectUserName"),
            process=data_map.get("NewProcessName") or data_map.get("Image"),
            parent_process=data_map.get("ParentProcessName") or data_map.get("ParentImage"),
            src_ip=data_map.get("IpAddress") or data_map.get("SourceIp"),
            dst_ip=data_map.get("DestinationIp"),
            command_line=data_map.get("CommandLine"),
            data=data_map,
        ))
    return events
