from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .models import Event


@dataclass(frozen=True, slots=True)
class GraphNode:
    id: str
    kind: str
    label: str


@dataclass(frozen=True, slots=True)
class GraphEdge:
    source: str
    target: str
    relation: str


def _node_id(kind: str, value: str) -> str:
    return f"{kind}:{value}".lower()


def build_graph(events: Iterable[Event]) -> tuple[list[GraphNode], list[GraphEdge]]:
    nodes: dict[str, GraphNode] = {}
    edges: set[GraphEdge] = set()

    def add(kind: str, value: str | None) -> str | None:
        if not value:
            return None
        node_id = _node_id(kind, value)
        nodes.setdefault(node_id, GraphNode(node_id, kind, value))
        return node_id

    for event in events:
        host = add("host", event.host)
        user = add("user", event.user)
        process = add("process", event.process)
        parent = add("process", event.parent_process)
        src_ip = add("ip", event.src_ip)
        dst_ip = add("ip", event.dst_ip)

        if user and host:
            edges.add(GraphEdge(user, host, "authenticated/on-host"))
        if parent and process:
            edges.add(GraphEdge(parent, process, "spawned"))
        if process and host:
            edges.add(GraphEdge(process, host, "executed-on"))
        if src_ip and host:
            edges.add(GraphEdge(src_ip, host, "connected-to"))
        if process and dst_ip:
            edges.add(GraphEdge(process, dst_ip, "connected-to"))

        if event.event_id in {"4698", "cron_job_created"} and host:
            task = add("persistence", event.data.get("task_name") or event.command_line or event.event_id)
            if task:
                edges.add(GraphEdge(host, task, "persistence"))
        if event.event_id in {"7045", "systemd_service_created"} and host:
            service = add("service", event.data.get("service_name") or event.data.get("unit") or event.event_id)
            if service:
                edges.add(GraphEdge(host, service, "service-change"))

    return sorted(nodes.values(), key=lambda n: (n.kind, n.label)), sorted(
        edges, key=lambda e: (e.source, e.target, e.relation)
    )


def render_mermaid(events: Iterable[Event]) -> str:
    nodes, edges = build_graph(events)
    lines = ["flowchart LR"]
    safe_ids: dict[str, str] = {}
    for idx, node in enumerate(nodes, 1):
        safe = f"N{idx}"
        safe_ids[node.id] = safe
        label = node.label.replace('"', "'")
        lines.append(f'    {safe}["{node.kind}: {label}"]')
    for edge in edges:
        lines.append(
            f'    {safe_ids[edge.source]} -->|{edge.relation}| {safe_ids[edge.target]}'
        )
    return "\n".join(lines)
