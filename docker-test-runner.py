#!/usr/bin/env python3
"""
Docker Test Runner - Alternative to running tests in Docker
This script simulates Docker container behavior for testing
"""

import os
import sys
import subprocess
import tempfile
import shutil
from pathlib import Path

def run_command(cmd, cwd=None, env=None):
    """Run command and return result"""
    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        if result.returncode != 0:
            print(f"Command failed with exit code {result.returncode}")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            return False
        print(f"Command succeeded")
        return True
    except subprocess.TimeoutExpired:
        print(f"Command timed out: {' '.join(cmd)}")
        return False
    except Exception as e:
        print(f"Error running command: {e}")
        return False

def setup_test_environment():
    """Setup environment similar to Docker container"""
    print("Setting up test environment...")

    # Create virtual environment if it doesn't exist
    venv_path = Path("/workspace/.venv")
    if not venv_path.exists():
        print("Creating virtual environment...")
        if not run_command([sys.executable, "-m", "venv", str(venv_path)]):
            return False

    # Activate virtual environment
    python_executable = venv_path / "bin" / "python"
    pip_executable = venv_path / "bin" / "pip"

    # Install dependencies
    print("Installing dependencies...")
    if not run_command([str(python_executable), "-m", "pip", "install", "--upgrade", "pip"]):
        return False

    if not run_command([str(python_executable), "-m", "pip", "install", "-e", "."]):
        return False

    return python_executable, pip_executable

def run_tests(test_type="unit"):
    """Run tests in simulated Docker environment"""
    print(f"Running {test_type} tests in simulated Docker environment...")

    python_executable, _ = setup_test_environment()
    if not python_executable:
        return False

    # Set environment variables as in Docker
    env = os.environ.copy()
    env["DOCKER_CONTAINER"] = "true"
    env["PYTHONPATH"] = "/workspace"

    if test_type == "unit":
        cmd = [
            str(python_executable), "-m", "pytest",
            "tests/unit", "-q", "--tb=line", "-n", "auto"
        ]
    elif test_type == "integration":
        cmd = [
            str(python_executable), "-m", "pytest",
            "tests/integration", "-q", "--tb=line"
        ]
    elif test_type == "all":
        cmd = [
            str(python_executable), "-m", "pytest",
            "tests/unit", "tests/integration", "-q", "--tb=line"
        ]
    else:
        print(f"Unknown test type: {test_type}")
        return False

    return run_command(cmd, env=env)

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python docker-test-runner.py <unit|integration|all>")
        sys.exit(1)

    test_type = sys.argv[1]

    print("=" * 50)
    print(f"🐳 Docker Test Runner - {test_type} tests")
    print("=" * 50)

    success = run_tests(test_type)

    print("=" * 50)
    if success:
        print("✅ Tests completed successfully!")
    else:
        print("❌ Tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()