#!/usr/bin/env python3
"""
Анализатор размера кода для мониторинга рефакторинга.
Используется для отслеживания прогресса уменьшения больших файлов.
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
        """Анализирует отдельный файл"""
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
            print(f"Ошибка чтения файла {file_path}: {e}")
            return FileStats(str(file_path), 0, 0, 0)

        return FileStats(str(file_path), lines, functions, classes)

    def find_python_files(self) -> List[Path]:
        """Находит все Python файлы в проекте"""
        python_files = []
        for root, dirs, files in os.walk(self.root_dir):
            # Исключаем некоторые директории
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['__pycache__', 'node_modules']]

            for file in files:
                if file.endswith('.py'):
                    python_files.append(Path(root) / file)

        return python_files

    def analyze_project(self) -> Dict[str, List[FileStats]]:
        """Анализирует весь проект"""
        python_files = self.find_python_files()
        results = {
            'critical': [],  # > 500 строк
            'warning': [],   # 300-500 строк
            'normal': [],    # < 300 строк
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
        """Печатает отчет"""
        print("🚀 АНАЛИЗ РАЗМЕРА КОДА AI-PROXY ПРОЕКТА")
        print("=" * 60)

        # Сводка
        summary = results['summary'][0]
        print("📊 СВОДКА:")
        print(f"  Всего файлов: {summary['total_files']}")
        print(",")
        print(f"  Всего функций: {summary['total_functions']}")
        print(f"  Всего классов: {summary['total_classes']}")
        print()

        # Критические файлы
        if results['critical']:
            print("🔴 КРИТИЧЕСКИЕ ФАЙЛЫ (>500 строк):")
            for file in sorted(results['critical'], key=lambda x: x.lines, reverse=True):
                print("6")
            print()

        # Предупреждения
        if results['warning']:
            print("🟡 ФАЙЛЫ ТРЕБУЮЩИЕ ВНИМАНИЯ (300-500 строк):")
            for file in sorted(results['warning'], key=lambda x: x.lines, reverse=True):
                print("6")
            print()

        # Рекомендации
        print("💡 РЕКОМЕНДАЦИИ:")
        if results['critical']:
            print("  • Разбить критические файлы на модули")
            print("  • Выделить общую логику в отдельные файлы")
            print("  • Создать фабрики для тестовых данных")
        if results['warning']:
            print("  • Рассмотреть возможность дальнейшего разделения")
            print("  • Проверить на наличие дублированного кода")

        if not results['critical'] and not results['warning']:
            print("  ✅ Отличная структура кода! Все файлы в норме.")

        print()
        print("📈 ЦЕЛИ РЕФАКТОРИНГА:")
        print("  • Максимальный размер файла: < 300 строк")
        print("  • Средний размер файла: < 150 строк")
        print("  • Количество файлов в модуле: < 10")


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
