#!/usr/bin/env python3
"""
Module dependency checker for AI Proxy project.

This script analyzes import dependencies between modules and helps
identify circular dependencies and maintain clean architecture.
"""

import os
import sys
import ast
import networkx as nx
from pathlib import Path
from typing import Dict, Set, List, Tuple
from collections import defaultdict


class ModuleDependencyAnalyzer:
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir)
        self.dependencies: Dict[str, Set[str]] = defaultdict(set)
        self.modules: Set[str] = set()

    def extract_module_name(self, file_path: Path) -> str:
        """Extract module name from file path."""
        try:
            rel_path = file_path.relative_to(self.root_dir)
            module_parts = []
            for part in rel_path.parts:
                if part.endswith('.py'):
                    module_parts.append(part[:-3])  # Remove .py extension
                elif part != '__pycache__':
                    module_parts.append(part)

            # Skip __init__.py files for module naming
            if module_parts and module_parts[-1] == '__init__':
                module_parts = module_parts[:-1]

            return '.'.join(module_parts)
        except ValueError:
            return str(file_path)

    def analyze_imports(self, file_path: Path) -> Set[str]:
        """Extract all imports from a Python file."""
        imports = set()
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            tree = ast.parse(content, filename=str(file_path))

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split('.')[0])

        except (SyntaxError, UnicodeDecodeError):
            pass

        return imports

    def build_dependency_graph(self) -> None:
        """Build dependency graph for all Python files."""
        for root, dirs, files in os.walk(self.root_dir):
            # Skip certain directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['__pycache__', 'node_modules']]

            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file
                    module_name = self.extract_module_name(file_path)

                    if module_name:
                        self.modules.add(module_name)
                        imports = self.analyze_imports(file_path)

                        # Filter imports to only include our project modules
                        for imp in imports:
                            if any(imp.startswith(prefix) for prefix in ['ai_proxy', 'tests']):
                                self.dependencies[module_name].add(imp)

    def detect_cycles(self) -> List[List[str]]:
        """Detect circular dependencies in the dependency graph."""
        # Create directed graph
        G = nx.DiGraph()

        for module, deps in self.dependencies.items():
            for dep in deps:
                G.add_edge(module, dep)

        # Find cycles
        cycles = []
        try:
            cycles = list(nx.simple_cycles(G))
        except nx.NetworkXError:
            pass

        return cycles

    def get_dependency_stats(self) -> Dict[str, int]:
        """Get dependency statistics."""
        stats = {
            'total_modules': len(self.modules),
            'modules_with_dependencies': len([m for m, deps in self.dependencies.items() if deps]),
            'total_dependencies': sum(len(deps) for deps in self.dependencies.values()),
            'max_dependencies': max((len(deps) for deps in self.dependencies.values()), default=0),
            'circular_dependencies': len(self.detect_cycles())
        }
        return stats

    def print_report(self) -> None:
        """Print dependency analysis report."""
        print("🔗 MODULE DEPENDENCY ANALYSIS")
        print("=" * 50)

        stats = self.get_dependency_stats()
        print("📊 STATISTICS:")
        print(f"  Total modules: {stats['total_modules']}")
        print(f"  Modules with dependencies: {stats['modules_with_dependencies']}")
        print(f"  Total dependencies: {stats['total_dependencies']}")
        print(f"  Max dependencies per module: {stats['max_dependencies']}")
        print(f"  Circular dependencies: {stats['circular_dependencies']}")
        print()

        # Show modules with most dependencies
        if self.dependencies:
            print("📈 MODULES WITH MOST DEPENDENCIES:")
            sorted_modules = sorted(
                self.dependencies.items(),
                key=lambda x: len(x[1]),
                reverse=True
            )[:10]

            for module, deps in sorted_modules:
                if deps:  # Only show modules with dependencies
                    print(f"  {module}: {len(deps)} dependencies")
            print()

        # Show circular dependencies
        cycles = self.detect_cycles()
        if cycles:
            print("🚨 CIRCULAR DEPENDENCIES DETECTED:")
            for i, cycle in enumerate(cycles, 1):
                print(f"  {i}. {' → '.join(cycle)}")
            print()
        else:
            print("✅ NO CIRCULAR DEPENDENCIES FOUND")
            print()

        # Show dependency details for specific modules
        print("📋 DEPENDENCY DETAILS:")

        # Show some key modules
        key_modules = [
            'ai_proxy.main',
            'ai_proxy.logdb.ingest',
            'tests.unit.test_logdb_stage_f',
            'tests.unit.test_logdb_stage_b'
        ]

        for module in key_modules:
            if module in self.dependencies and self.dependencies[module]:
                print(f"\n  {module}:")
                for dep in sorted(self.dependencies[module]):
                    print(f"    └─ {dep}")
            elif module in self.modules:
                print(f"\n  {module}: (no dependencies)")

        print()
        print("💡 RECOMMENDATIONS:")
        if stats['circular_dependencies'] > 0:
            print("  • Fix circular dependencies to improve maintainability")
        if stats['max_dependencies'] > 10:
            print("  • Consider splitting modules with many dependencies")
        if stats['modules_with_dependencies'] / stats['total_modules'] < 0.5:
            print("  • Good modularity - most modules have clear responsibilities")


def main():
    if len(sys.argv) > 1:
        root_dir = sys.argv[1]
    else:
        root_dir = "/home/tass/myprojects/ai-proxy"

    try:
        analyzer = ModuleDependencyAnalyzer(root_dir)
        analyzer.build_dependency_graph()
        analyzer.print_report()
    except ImportError:
        print("❌ NetworkX library not found. Install with: pip install networkx")
        sys.exit(1)


if __name__ == "__main__":
    main()
