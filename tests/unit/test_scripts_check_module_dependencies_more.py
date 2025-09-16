import importlib.util
import os
import sys
from types import SimpleNamespace


def _load_deps_module():
    spec = importlib.util.spec_from_file_location(
        "deps", os.path.join(os.getcwd(), "scripts", "check_module_dependencies.py")
    )
    deps_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deps_mod)
    return deps_mod


def test_print_report_various_branches(capsys):
    # inject fake networkx before loading module
    class _FakeDiGraph:
        def __init__(self):
            self.edges = []

        def add_edge(self, a, b):
            self.edges.append((a, b))

    def _simple_cycles(graph):
        return []

    fake_nx = SimpleNamespace(DiGraph=_FakeDiGraph, simple_cycles=_simple_cycles)
    sys.modules["networkx"] = fake_nx

    deps_mod = _load_deps_module()

    analyzer = deps_mod.ModuleDependencyAnalyzer("/tmp")

    # craft modules and dependencies to hit printing branches
    analyzer.modules = {
        "ai_proxy.main",
        "ai_proxy.logdb.ingest",
        "tests.unit.bundle.test_creation",
    }
    analyzer.dependencies = {
        "tests.unit.bundle.test_creation": {"ai_proxy"},
        "tests.unit.ingest.test_cli": {"ai_proxy", "tests"},
        "ai_proxy.main": {"ai_proxy"},
    }

    # call print_report and assert outputs
    analyzer.print_report()
    captured = capsys.readouterr()
    assert "MODULE DEPENDENCY ANALYSIS" in captured.out
    assert "NO CIRCULAR DEPENDENCIES FOUND" in captured.out
    assert "MODULES WITH MOST DEPENDENCIES" in captured.out

    del sys.modules["networkx"]


def test_detect_cycles_reports_cycles():
    # inject fake networkx that reports a cycle
    class _FakeDiGraph:
        def __init__(self):
            self.edges = []

        def add_edge(self, a, b):
            self.edges.append((a, b))

    def _simple_cycles(graph):
        return [["a", "b", "c"]]

    sys.modules["networkx"] = SimpleNamespace(
        DiGraph=_FakeDiGraph, simple_cycles=_simple_cycles
    )

    deps_mod = _load_deps_module()
    analyzer = deps_mod.ModuleDependencyAnalyzer("/tmp")
    analyzer.dependencies = {"a": {"b"}, "b": {"c"}, "c": {"a"}}

    cycles = analyzer.detect_cycles()
    assert cycles == [["a", "b", "c"]]

    del sys.modules["networkx"]
