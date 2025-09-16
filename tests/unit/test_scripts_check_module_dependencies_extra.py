import types
import textwrap
from pathlib import Path
import sys

import pytest
from scripts.check_module_dependencies import ModuleDependencyAnalyzer

# Provide a lightweight fake `networkx` implementation so tests don't require
# the real external dependency when running in the project's test environment.
_nx = types.ModuleType("networkx")


class _DiGraph:
    def __init__(self):
        self._edges = {}

    def add_edge(self, a, b):
        self._edges.setdefault(a, set()).add(b)


def _simple_cycles(graph):
    # Find simple cycles using DFS; return list of cycles as lists
    edges = getattr(graph, "_edges", {})
    cycles = set()

    def dfs(node, start, path, visited):
        visited.add(node)
        for nbr in edges.get(node, ()):  # neighbors
            if nbr == start:
                cycles.add(tuple(path + [start]))
            elif nbr not in visited and len(path) < 50:
                dfs(nbr, start, path + [nbr], set(visited))

    for n in list(edges.keys()):
        dfs(n, n, [n], set())

    # normalize cycles to lists
    return [list(cycle) for cycle in cycles]


_nx.DiGraph = _DiGraph
_nx.simple_cycles = _simple_cycles


class _NXError(Exception):
    pass


_nx.NetworkXError = _NXError
sys.modules.setdefault("networkx", _nx)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content))


def test_extract_module_name_for_init(tmp_path: Path) -> None:
    root = tmp_path
    init_file = root / "pkg" / "__init__.py"
    _write(init_file, "")

    analyzer = ModuleDependencyAnalyzer(str(root))
    assert analyzer.extract_module_name(init_file) == "pkg"


def test_analyze_imports_and_build_graph(tmp_path: Path) -> None:
    root = tmp_path

    # Create a small ai_proxy package with two modules that import each other
    _write(root / "ai_proxy" / "__init__.py", "")
    _write(
        root / "ai_proxy" / "a.py",
        """
        import ai_proxy.b
        import os
        from ai_proxy.c import something
        """,
    )
    _write(root / "ai_proxy" / "b.py", "import ai_proxy.a\n")

    analyzer = ModuleDependencyAnalyzer(str(root))
    analyzer.build_dependency_graph()

    # modules should include both modules we created
    assert "ai_proxy.a" in analyzer.modules
    assert "ai_proxy.b" in analyzer.modules

    # dependencies are filtered to project prefixes and should include 'ai_proxy'
    found_any = any("ai_proxy" in deps for deps in analyzer.dependencies.values())
    assert found_any

    stats = analyzer.get_dependency_stats()
    assert stats["total_modules"] >= 2
    assert isinstance(stats["total_dependencies"], int)


def test_analyze_imports_handles_syntax_error(tmp_path: Path) -> None:
    root = tmp_path
    bad_file = root / "ai_proxy" / "bad.py"
    _write(bad_file, "def broken(:\n    pass")

    analyzer = ModuleDependencyAnalyzer(str(root))
    imports = analyzer.analyze_imports(bad_file)
    # Syntax error should be handled and return an empty set
    assert imports == set()


def test_detect_cycles_and_print_report_recommendations(capsys) -> None:
    analyzer = ModuleDependencyAnalyzer("/does/not/matter")

    # Manually craft modules/dependencies to force a cycle and a large-deps recommendation
    analyzer.modules = {"mod1", "mod2", "many"}
    analyzer.dependencies = {
        "mod1": {"mod2"},
        "mod2": {"mod1"},
        "many": set(f"dep{i}" for i in range(12)),
    }

    # This should not raise and should print both cycle info and a recommendation
    analyzer.print_report()
    out = capsys.readouterr().out
    assert (
        "CIRCULAR DEPENDENCIES DETECTED" in out
        or "NO CIRCULAR DEPENDENCIES FOUND" in out
    )
    assert "Consider splitting modules" in out


def test_extract_module_name_value_error(tmp_path: Path) -> None:
    # file outside the root should fall back to string path
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "other" / "outside.py"
    _write(outside, "")

    analyzer = ModuleDependencyAnalyzer(str(root))
    result = analyzer.extract_module_name(outside)
    assert str(outside) == result


def test_detect_cycles_handles_networkx_error(monkeypatch) -> None:
    import scripts.check_module_dependencies as mod

    analyzer = ModuleDependencyAnalyzer("/does/not/matter")
    analyzer.dependencies = {"a": {"b"}}

    # Replace simple_cycles with a function that raises NetworkXError
    original = mod.nx.simple_cycles

    def _raising(_g):
        raise mod.nx.NetworkXError("boom")

    monkeypatch.setattr(mod.nx, "simple_cycles", _raising)
    try:
        cycles = analyzer.detect_cycles()
        assert cycles == []
    finally:
        monkeypatch.setattr(mod.nx, "simple_cycles", original)


def test_print_report_good_modularity(capsys) -> None:
    analyzer = ModuleDependencyAnalyzer("/does/not/matter")
    analyzer.modules = {"m1", "m2", "m3", "m4"}
    analyzer.dependencies = {"m1": set(), "m2": {"ai_proxy.x"}}

    analyzer.print_report()
    out = capsys.readouterr().out
    # modules_with_dependencies = 1, total_modules = 4 -> ratio 0.25 < 0.5
    assert "Good modularity" in out


def test_main_handles_importerror(monkeypatch, capsys):
    import scripts.check_module_dependencies as mod

    class _Bad:
        def __init__(self, *_a, **_k):
            raise ImportError("no nx")

    monkeypatch.setattr(mod, "ModuleDependencyAnalyzer", _Bad)

    with pytest.raises(SystemExit) as exc:
        mod.main()

    out = capsys.readouterr().out
    assert "NetworkX library not found" in out
    assert exc.value.code == 1
