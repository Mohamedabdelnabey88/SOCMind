from __future__ import annotations

from collections import defaultdict

from .models import Event


def render_process_tree(events: list[Event]) -> str:
    children: dict[str, set[str]] = defaultdict(set)
    seen: set[str] = set()

    for event in events:
        if event.process:
            seen.add(event.process)
        if event.parent_process and event.process:
            seen.add(event.parent_process)
            children[event.parent_process].add(event.process)

    child_names = {child for values in children.values() for child in values}
    roots = sorted(seen - child_names) or sorted(seen)

    lines = ["SOCMind Process Ancestry", "=" * 24]

    def walk(node: str, prefix: str = "") -> None:
        lines.append(f"{prefix}{node}")
        for idx, child in enumerate(sorted(children.get(node, []))):
            connector = "└── " if idx == len(children[node]) - 1 else "├── "
            walk(child, prefix + connector)

    for root in roots:
        walk(root)
    return "\n".join(lines)
