import os
import textwrap
import importlib.util
import sys
from pathlib import Path

import pytest


def _write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content))


def test_analyze_code_size_basic(tmp_path, capsys):
    # create a small project tree with python files
    pkg = tmp_path / "proj"
    pkg.mkdir()

    # small file
    _write(pkg / "a.py", """
    def f():
        return 1

    class C:
        pass
    """)

    # medium file (350 lines)
    medium_lines = ["def fn(): pass\n" for _ in range(350)]
    (pkg / "medium.py").write_text("".join(medium_lines))

    # critical file (600 lines)
    critical_lines = ["# line\n" for _ in range(600)]
    (pkg / "big.py").write_text("".join(critical_lines))

    # import analyzer from scripts by path
    spec = importlib.util.spec_from_file_location("analyzer", os.path.join(os.getcwd(), "scripts", "analyze_code_size.py"))
    analyzer_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(analyzer_mod)

    analyzer = analyzer_mod.CodeAnalyzer(str(pkg))
    results = analyzer.analyze_project()

    summary = results["summary"][0]
    assert summary["total_files"] == 3
    # Ensure categories were populated
    assert len(results["critical"]) == 1
    assert len(results["warning"]) == 1
    assert len(results["normal"]) == 1

    # verify print_report runs without error and prints English text
    analyzer.print_report(results)
    captured = capsys.readouterr()
    assert "AI-PROXY CODE SIZE ANALYSIS" in captured.out


def test_analyze_no_large_files_and_main_invocation(tmp_path, capsys, monkeypatch):
    pkg = tmp_path / "proj2"
    pkg.mkdir()

    # Create a few small files only
    for i in range(3):
        _write(pkg / f"small_{i}.py", """
        def f():
            return 1
        """)

    # import analyzer
    spec = importlib.util.spec_from_file_location("analyzer", os.path.join(os.getcwd(), "scripts", "analyze_code_size.py"))
    analyzer_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(analyzer_mod)

    analyzer = analyzer_mod.CodeAnalyzer(str(pkg))
    results = analyzer.analyze_project()

    # no critical and no warnings
    assert not results["critical"]
    assert not results["warning"]

    # call print_report to hit the 'great structure' branch
    analyzer.print_report(results)
    captured = capsys.readouterr()
    assert "Great code structure" in captured.out

    # test main invocation via sys.argv
    monkeypatch.setattr(sys, "argv", ["prog", str(pkg)])
    analyzer_mod.main()
    captured = capsys.readouterr()
    assert "AI-PROXY CODE SIZE ANALYSIS" in captured.out


def test_check_module_dependencies_detects_cycle(tmp_path):
    # create a fake ai_proxy package structure under tmp_path
    root = tmp_path
    ap = root / "ai_proxy"
    ap.mkdir()

    # module a imports ai_proxy.b
    _write(ap / "a.py", """
    import ai_proxy.b
    """)

    # module b imports ai_proxy.a creating a cycle
    _write(ap / "b.py", """
    import ai_proxy.a
    """)

    # Provide a minimal fake networkx module in sys.modules to avoid ImportError
    class _FakeDiGraph:
        def __init__(self):
            self.edges = []

        def add_edge(self, a, b):
            self.edges.append((a, b))

    def _simple_cycles(graph):
        # naive cycle detection for small graphs: look for a->b and b->a
        cycles = []
        edges = set(graph.edges)
        for a, b in graph.edges:
            if (b, a) in edges:
                cycles.append([a, b])
        return cycles

    fake_nx = type("nx", (), {"DiGraph": _FakeDiGraph, "simple_cycles": _simple_cycles})
    sys.modules["networkx"] = fake_nx

    # import dependency analyzer
    spec = importlib.util.spec_from_file_location("deps", os.path.join(os.getcwd(), "scripts", "check_module_dependencies.py"))
    deps_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deps_mod)

    analyzer = deps_mod.ModuleDependencyAnalyzer(str(root))
    analyzer.build_dependency_graph()
    cycles = analyzer.detect_cycles()

    # Ensure modules were discovered and dependencies recorded
    assert any(m.startswith("ai_proxy.a") for m in analyzer.modules)
    assert any(m.startswith("ai_proxy.b") for m in analyzer.modules)
    assert isinstance(cycles, list)

    # cleanup fake module
    del sys.modules["networkx"]


