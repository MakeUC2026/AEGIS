"""M2 execution and import boundary (B-05, D-03, X-6; PRD D-11, §3.3).

M2's `app/firewall/` code never runs anything on a real host and never imports a web
framework: no subprocess, sockets or HTTP clients; no os.system/popen/exec*, eval or exec;
no FastAPI or Starlette. Files owned by other machines (ports.py by M1; judge, risky
history and forensics by M3) are excluded: they are checked by their owners.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

FIREWALL = pathlib.Path(__file__).resolve().parents[2] / "app" / "firewall"
NOT_M2 = {"ports.py", "judge.py", "risky_history.py", "risky_patterns.py", "forensics_read.py"}
FORBIDDEN_MODULES = {
    "subprocess", "socket", "requests", "httpx", "aiohttp", "urllib.request", "http.client",
    "fastapi", "starlette", "pty", "multiprocessing", "ctypes",
}  # fmt: skip
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_OS = {"system", "popen", "spawnl", "spawnv", "execv", "execl", "fork", "kill"}

M2_FILES = sorted(p for p in FIREWALL.glob("*.py") if p.name not in NOT_M2)


def _imports(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_there_are_m2_files_to_check() -> None:
    assert len(M2_FILES) >= 10


@pytest.mark.parametrize("path", M2_FILES, ids=lambda p: p.name)
def test_no_forbidden_imports(path: pathlib.Path) -> None:
    imported = _imports(ast.parse(path.read_text()))
    bad = {m for m in imported if m in FORBIDDEN_MODULES or m.split(".")[0] in FORBIDDEN_MODULES}
    assert not bad, f"{path.name} imports {sorted(bad)}"


@pytest.mark.parametrize("path", M2_FILES, ids=lambda p: p.name)
def test_no_dynamic_execution_or_os_process_calls(path: pathlib.Path) -> None:
    for node in ast.walk(ast.parse(path.read_text())):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            assert func.id not in FORBIDDEN_CALLS, f"{path.name}: {func.id}()"
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            assert not (func.value.id == "os" and func.attr in FORBIDDEN_OS), (
                f"{path.name}: os.{func.attr}()"
            )
