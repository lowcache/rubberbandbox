"""Structural guards: the core knows no pack, packs see only the core's public API,
and only the door holds tool adapters."""

import ast
from pathlib import Path

from rubbersand.packs.messaging import build

PKG = Path(__file__).resolve().parent.parent / "rubbersand"


def imports(path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name, 0
        elif isinstance(node, ast.ImportFrom):
            yield node.module or "", node.level


def test_core_imports_no_pack():
    for path in (PKG / "core").rglob("*.py"):
        for mod, level in imports(path):
            assert "packs" not in mod, f"{path.name} imports {mod}"
            assert level <= 1, f"{path.name} reaches outside core"


def test_packs_and_clerks_use_only_the_core_public_api():
    for path in [*(PKG / "packs").rglob("*.py"), *(PKG / "clerks").rglob("*.py")]:
        for mod, level in imports(path):
            if level:  # relative import within the same pack
                assert level == 1, f"{path} reaches outside its pack"
                continue
            if mod.startswith("rubbersand"):
                assert mod == "rubbersand.core", f"{path} imports {mod}"
            if mod.startswith("rubbersand.packs"):
                raise AssertionError(f"{path} imports another pack")


def test_packs_never_call_adapters_directly():
    for path in (PKG / "packs").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr != "execute" or path.name == "sim.py", f"{path} calls .execute()"


def test_only_the_door_holds_the_adapter():
    sb, channel, _ = build()
    holders = [name for name, v in vars(sb).items() if v is channel]
    assert holders == []
    assert any(v is channel for v in vars(sb._door)["_adapters"].values())
