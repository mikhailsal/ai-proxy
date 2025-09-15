#!/usr/bin/env python3
"""
Direct Test Runner - Run tests without external commands
"""

import os
import sys
import subprocess
import importlib.util

def run_tests():
    """Run tests directly"""
    print("🚀 Running AI Proxy Tests...")

    # Set environment variables
    os.environ["DOCKER_CONTAINER"] = "true"
    os.environ["HOST_UID"] = str(os.getuid())
    os.environ["HOST_GID"] = str(os.getgid())

    # Change to workspace directory
    os.chdir("/workspace")

    # Try to run pytest directly
    try:
        # Import pytest if available
        import pytest
        print("✅ Pytest available, running tests...")

        # Run unit tests
        print("\n📋 Running unit tests...")
        result = pytest.main([
            "tests/unit",
            "-q",
            "--tb=line",
            "-n", "auto",
            "--disable-warnings"
        ])

        if result == 0:
            print("✅ Unit tests passed!")
        else:
            print(f"❌ Unit tests failed with code {result}")
            return False

        # Run integration tests
        print("\n🔗 Running integration tests...")
        if os.path.exists("tests/integration") and any(f.endswith(".py") for f in os.listdir("tests/integration") if f.startswith("test_")):
            result = pytest.main([
                "tests/integration",
                "-q",
                "--tb=line",
                "--disable-warnings"
            ])

            if result == 0:
                print("✅ Integration tests passed!")
            else:
                print(f"❌ Integration tests failed with code {result}")
                return False
        else:
            print("ℹ️ No integration tests found, skipping...")

        print("\n🎉 All tests completed successfully!")
        return True

    except ImportError:
        print("❌ Pytest not available. Installing...")

        # Try to install pytest
        try:
            import pip
            pip.main(["install", "pytest", "pytest-xdist", "pytest-asyncio"])
            print("✅ Pytest installed, please run again")
            return False
        except:
            print("❌ Could not install pytest")
            return False
    except Exception as e:
        print(f"❌ Error running tests: {e}")
        return False

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)