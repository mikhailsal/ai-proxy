#!/usr/bin/env python3
"""
Code size analyzer for monitoring refactoring progress.
Used to track reduction of large files across the project.
"""

import os
import sys
from pathlib import Path
from typing import List, Tuple, Dict
from dataclasses import dataclass


@dataclass
class FileStats:
    path: str
    lines: int
    functions: int
    classes: int


class CodeAnalyzer:
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir)

    def analyze_file(self, file_path: Path) -> FileStats:
        """Analyze a single file"""
        lines = 0
        functions = 0
        classes = 0

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    lines += 1
                    stripped = line.strip()
                    if stripped.startswith('def '):
                        functions += 1
                    elif stripped.startswith('class '):
                        classes += 1
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return FileStats(str(file_path), 0, 0, 0)

        return FileStats(str(file_path), lines, functions, classes)

    def find_python_files(self) -> List[Path]:
        """Find all Python files in the project"""
        python_files = []
        for root, dirs, files in os.walk(self.root_dir):
            # Исключаем некоторые директории
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['__pycache__', 'node_modules']]

            for file in files:
                if file.endswith('.py'):
                    python_files.append(Path(root) / file)

        return python_files

    def analyze_project(self) -> Dict[str, List[FileStats]]:
        """Analyze the entire project"""
        python_files = self.find_python_files()
        results = {
            'critical': [],  # > 500 lines
            'warning': [],   # 300-500 lines
            'normal': [],    # < 300 lines
            'summary': []
        }

        total_lines = 0
        total_functions = 0
        total_classes = 0

        for file_path in python_files:
            stats = self.analyze_file(file_path)
            total_lines += stats.lines
            total_functions += stats.functions
            total_classes += stats.classes

            if stats.lines > 500:
                results['critical'].append(stats)
            elif stats.lines > 300:
                results['warning'].append(stats)
            else:
                results['normal'].append(stats)

        results['summary'] = [{
            'total_files': len(python_files),
            'total_lines': total_lines,
            'total_functions': total_functions,
            'total_classes': total_classes,
            'critical_files': len(results['critical']),
            'warning_files': len(results['warning']),
            'normal_files': len(results['normal'])
        }]

        return results

    def print_report(self, results: Dict[str, List[FileStats]]) -> None:
        """Print the analysis report"""
        print("🚀 AI-PROXY CODE SIZE ANALYSIS")
        print("=" * 60)

        # Summary
        summary = results['summary'][0]
        print("📊 SUMMARY:")
        print(f"  Total files: {summary['total_files']}")
        print(f"  Total functions: {summary['total_functions']}")
        print(f"  Total classes: {summary['total_classes']}")
        print()

        # Critical files
        if results['critical']:
            print("🔴 CRITICAL FILES (>500 lines):")
            for file in sorted(results['critical'], key=lambda x: x.lines, reverse=True):
                print(f"  {file.path}: {file.lines} lines, {file.functions} functions, {file.classes} classes")
            print()

        # Warnings
        if results['warning']:
            print("🟡 FILES REQUIRING ATTENTION (300-500 lines):")
            for file in sorted(results['warning'], key=lambda x: x.lines, reverse=True):
                print(f"  {file.path}: {file.lines} lines, {file.functions} functions, {file.classes} classes")
            print()

        # Recommendations
        print("💡 RECOMMENDATIONS:")
        if results['critical']:
            print("  • Split critical files into modules")
            print("  • Extract common logic into separate files")
            print("  • Create test data factories")
        if results['warning']:
            print("  • Consider further splitting")
            print("  • Check for duplicated code")

        if not results['critical'] and not results['warning']:
            print("  ✅ Great code structure — all files are within size targets.")

        print()
        print("📈 REFACTORING GOALS:")
        print("  • Max file size: < 300 lines")
        print("  • Average file size: < 150 lines")
        print("  • Files per module: < 10")


def main():
    if len(sys.argv) > 1:
        root_dir = sys.argv[1]
    else:
        root_dir = "/home/tass/myprojects/ai-proxy"

    analyzer = CodeAnalyzer(root_dir)
    results = analyzer.analyze_project()
    analyzer.print_report(results)


if __name__ == "__main__":
    main()
