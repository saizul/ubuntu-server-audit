"""Check registration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ubuntu_server_audit.context import AuditContext
from ubuntu_server_audit.model import CATEGORIES, CheckSpec, Outcome, Severity

CheckFn = Callable[[AuditContext], Outcome]


@dataclass(frozen=True)
class Check:
    spec: CheckSpec
    fn: CheckFn


REGISTRY: dict[str, Check] = {}


def check(
    id: str,
    title: str,
    *,
    category: str,
    severity: Severity,
    fix: str,
    needs_root: bool = False,
    references: tuple[str, ...] = (),
    description: str = "",
) -> Callable[[CheckFn], CheckFn]:
    """Register a check function. ``needs_root`` checks are skipped up front for normal users."""
    if category not in CATEGORIES:
        raise ValueError(f"unknown category {category!r}")

    def decorator(fn: CheckFn) -> CheckFn:
        if id in REGISTRY:
            raise ValueError(f"duplicate check id {id}")
        spec = CheckSpec(
            id, title, category, severity, fix, needs_root, references, description or (fn.__doc__ or "").strip()
        )
        REGISTRY[id] = Check(spec, fn)
        return fn

    return decorator


def all_checks() -> list[Check]:
    import ubuntu_server_audit.checks  # noqa: F401 - registers the checks

    order = list(CATEGORIES)
    return sorted(REGISTRY.values(), key=lambda c: (order.index(c.spec.category), c.spec.id))
