"""inventory_agent.py must import on the oldest Python the installers accept.

AssetlyAgent_macOS_postinstall.sh takes any python.org build >= 3.8, and
AssetlyAgent_Linux.sh takes whatever python3 the distribution ships (3.8 on
Ubuntu 20.04, 3.9 on Debian 11). The tests themselves run on a newer Python,
so they cannot notice when the agent stops working on those.

ast.parse(feature_version=...) is not enough on its own: `def f(x: str | None)`
is valid 3.8 grammar and only fails when the def statement runs, because the
annotation is evaluated then. That is how the agent shipped a TypeError at
import on 3.9 -- before self-update, so an affected machine could not even
update its way out of it.
"""
import ast
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parent.parent / "inventory_agent.py"
FLOOR = (3, 8)

# Builtins that only became subscriptable at runtime in 3.9 (PEP 585).
PEP585_BUILTINS = {"list", "dict", "tuple", "set", "frozenset", "type"}


def _tree():
    return ast.parse(AGENT.read_text(encoding="utf-8"))


def _runtime_annotations(tree):
    """Annotations Python evaluates when the module is imported: every def's
    parameters and return, and variable annotations at module or class level.
    (A local variable's annotation inside a function body is never evaluated.)"""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
                if arg is not None and arg.annotation is not None:
                    yield arg.annotation
            if node.returns is not None:
                yield node.returns
        if isinstance(node, (ast.Module, ast.ClassDef)):
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign):
                    yield stmt.annotation


def _postponed_annotations(tree) -> bool:
    return any(
        isinstance(stmt, ast.ImportFrom)
        and stmt.module == "__future__"
        and any(alias.name == "annotations" for alias in stmt.names)
        for stmt in tree.body
    )


def test_agent_parses_as_the_oldest_supported_python():
    ast.parse(AGENT.read_text(encoding="utf-8"), feature_version=FLOOR)


def test_agent_has_no_annotations_that_fail_at_import_on_the_oldest_python():
    tree = _tree()
    if _postponed_annotations(tree):
        pytest.skip("annotations are postponed, so none are evaluated at import")

    source = AGENT.read_text(encoding="utf-8")
    offenders = []
    for annotation in _runtime_annotations(tree):
        for node in ast.walk(annotation):
            union = isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr)
            generic = (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Name)
                and node.value.id in PEP585_BUILTINS
            )
            if union or generic:
                offenders.append(f"line {annotation.lineno}: {ast.get_source_segment(source, annotation)}")
                break
    assert not offenders, (
        "these annotations raise TypeError at import on Python "
        f"{FLOOR[0]}.{FLOOR[1]}; drop the hint, as the rest of the file does:\n  "
        + "\n  ".join(offenders)
    )
