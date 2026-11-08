"""Seam wiring: return the real or fake implementation of each contract (M1 A-03).

`AEGIS_USE_FAKES` is a comma list of seams to fake: firewall, read, admin, risky,
judge, arena. Each machine's branch fakes only what it lacks; at integration the
value is empty and every seam resolves to its real `create()` factory.

Provider contract: each real module exposes `create() -> <Port>`.
Owned by M1 (shared file, §0.2 rule 3).
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable
from typing import Any, cast

from app.config import get_settings
from app.contracts.arena import ArenaServicePort
from app.contracts.fakes import (
    FakeArenaService,
    FakeFirewall,
    FakeFirewallAdmin,
    FakeFirewallRead,
    InMemoryRiskyHistory,
    StubJudge,
)
from app.contracts.fakes.dev_script import dev_responder
from app.contracts.firewall import FirewallPort
from app.contracts.firewall_admin import FirewallAdminPort
from app.contracts.firewall_read import FirewallReadPort
from app.contracts.sentinel import JudgePort, RiskyHistoryPort

REAL_FACTORIES: dict[str, str] = {
    "firewall": "app.firewall.interface:create",
    "read": "app.firewall.read_api:create",
    "admin": "app.firewall.admin_api:create",
    "risky": "app.firewall.risky_history:create",
    "judge": "app.firewall.judge:create",
    "arena": "app.arena.service:create",
}
SEAMS: frozenset[str] = frozenset(REAL_FACTORIES)


class PortUnavailable(RuntimeError):
    """A seam has neither a real implementation on this branch nor a fake enabled."""


_instances: dict[str, Any] = {}


def _setting(env_name: str, attr: str) -> str:
    """Process environment first (CI, tests, deploys), else the app settings, which read .env."""
    value = os.environ.get(env_name)
    return value if value is not None else getattr(get_settings(), attr)


def fake_script() -> str:
    return _setting("AEGIS_FAKE_SCRIPT", "fake_script")


def fake_seams() -> frozenset[str]:
    raw = _setting("AEGIS_USE_FAKES", "use_fakes")
    names = frozenset(n.strip() for n in raw.split(",") if n.strip())
    unknown = names - SEAMS
    if unknown:
        raise ValueError(f"AEGIS_USE_FAKES has unknown seam(s): {', '.join(sorted(unknown))}")
    return names


def _fake(name: str) -> Any:
    if name == "firewall":
        read = get_firewall_read() if "read" in fake_seams() else None
        responder = dev_responder if fake_script() == "dev" else None

        def observe(ctx: Any, message_id: str, text: str, result: Any) -> None:
            if isinstance(read, FakeFirewallRead):
                read.set_secret(ctx.fw_session_id, ctx.secret)
                read.record_turn(ctx.fw_session_id, message_id, text, result)

        return FakeFirewall(responder=responder, observer=observe if read is not None else None)
    if name == "admin":
        fw = get_firewall()
        return FakeFirewallAdmin(fw if isinstance(fw, FakeFirewall) else None)
    factories: dict[str, Callable[[], Any]] = {
        "read": FakeFirewallRead,
        "risky": InMemoryRiskyHistory,
        "judge": StubJudge,
        "arena": FakeArenaService,
    }
    return factories[name]()


def _real(name: str) -> Any:
    module_name, _, attr = REAL_FACTORIES[name].partition(":")
    try:
        # module_name comes only from the constant REAL_FACTORIES allowlist, never from input.
        module = importlib.import_module(module_name)  # nosemgrep: non-literal-import
    except ModuleNotFoundError as exc:
        raise PortUnavailable(
            f"seam {name!r}: {module_name} is not on this branch; add {name!r} to AEGIS_USE_FAKES"
        ) from exc
    return getattr(module, attr)()


def _get(name: str) -> Any:
    if name not in _instances:
        _instances[name] = _fake(name) if name in fake_seams() else _real(name)
    return _instances[name]


def override(name: str, implementation: Any) -> None:
    """Tests: pin a specific implementation for a seam."""
    if name not in SEAMS:
        raise ValueError(name)
    _instances[name] = implementation


def reset() -> None:
    _instances.clear()


def get_firewall() -> FirewallPort:
    return cast(FirewallPort, _get("firewall"))


def get_firewall_read() -> FirewallReadPort:
    return cast(FirewallReadPort, _get("read"))


def get_firewall_admin() -> FirewallAdminPort:
    return cast(FirewallAdminPort, _get("admin"))


def get_risky_history() -> RiskyHistoryPort:
    return cast(RiskyHistoryPort, _get("risky"))


def get_judge() -> JudgePort:
    return cast(JudgePort, _get("judge"))


def get_arena_service() -> ArenaServicePort:
    return cast(ArenaServicePort, _get("arena"))
