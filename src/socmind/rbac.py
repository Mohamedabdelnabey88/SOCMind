from __future__ import annotations

from dataclasses import dataclass


ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({
        "case.read",
        "lead.read",
        "reasoning.read",
    }),
    "analyst": frozenset({
        "case.read",
        "case.acknowledge",
        "case.note",
        "lead.read",
        "reasoning.read",
    }),
    "senior-analyst": frozenset({
        "case.read",
        "case.acknowledge",
        "case.note",
        "case.assign",
        "case.transition",
        "lead.read",
        "reasoning.read",
        "detection.review",
    }),
    "lead": frozenset({
        "case.read",
        "case.acknowledge",
        "case.note",
        "case.assign",
        "case.transition",
        "lead.read",
        "reasoning.read",
        "detection.review",
        "audit.read",
    }),
    "admin": frozenset({"*"}),
}


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    role: str
    source: str

    def can(self, permission: str) -> bool:
        granted = ROLE_PERMISSIONS.get(self.role, frozenset())
        return "*" in granted or permission in granted


def normalize_role(role: str | None, *, default: str = "viewer") -> str:
    value = (role or default).strip().lower()
    if value not in ROLE_PERMISSIONS:
        raise ValueError(f"Unknown SOCMind role: {value}")
    return value


def require_permission(principal: Principal, permission: str) -> None:
    if not principal.can(permission):
        raise PermissionError(
            f"Role '{principal.role}' does not grant permission '{permission}'"
        )
