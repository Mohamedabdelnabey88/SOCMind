from __future__ import annotations

from dataclasses import dataclass


ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({
        "case.read",
        "lead.read",
        "reasoning.read",
        "evidence.read",
    }),
    "analyst": frozenset({
        "case.read",
        "case.acknowledge",
        "case.note",
        "lead.read",
        "reasoning.read",
        "evidence.read",
        "evidence.request",
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
        "detection.manage",
        "evidence.read",
        "evidence.request",
        "evidence.manage",
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
        "detection.manage",
        "detection.approve",
        "detection.promote",
        "audit.read",
        "evidence.read",
        "evidence.request",
        "evidence.manage",
        "evidence.waive",
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
