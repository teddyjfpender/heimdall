#!/usr/bin/env python3
"""
Test runner for Heimdall Starknet Authentication Service.

This script provides a simple way to run the test suite with proper path setup.
"""

import os
import sys
import subprocess
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "application" / "starknet" / "enclave"))

def run_tests():
    """Run the test suite."""
    print("Running Heimdall Test Suite")
    print("=" * 50)
    
    # Set PYTHONPATH to include project root
    env = os.environ.copy()
    env['PYTHONPATH'] = str(project_root)
    
    # Run pytest with the test directory, excluding problematic tests if needed
    try:
        # First try to run all tests
        result = subprocess.run([
            sys.executable, 
            "-m", "pytest",
            "tests/",
            "-v",
            "--tb=long",  # Show full traceback for better debugging
            "-x",  # Stop on first failure to get clearer error messages
            "--import-mode=importlib"  # Use importlib mode for better import handling
        ], env=env, cwd=project_root, check=False)
        
        if result.returncode != 0:
            print("\nNote: Some tests failed. This might be due to missing optional dependencies.")
            print("Core unit tests should still pass.")
            
        return result.returncode
    except Exception as e:
        print(f"Error running tests: {e}")
        return 1

if __name__ == "__main__":
    exit_code = run_tests()
    sys.exit(exit_code)