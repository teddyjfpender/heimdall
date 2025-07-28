#!/usr/bin/env python3
"""
Enhanced test runner for Heimdall with comprehensive reporting and environment management.

This script provides a unified interface for running different types of tests
with proper environment setup, cleanup, and reporting.
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from config.settings import settings
    from config.test_environments import test_environment
    from tests.utils.database import cleanup_all_test_resources
except ImportError:
    print("⚠️  Warning: Could not import configuration. Run 'make setup-dev' first.")
    settings = None


class TestRunner:
    """Enhanced test runner with environment management."""
    
    def __init__(self):
        self.project_root = PROJECT_ROOT
        self.test_results: Dict[str, Any] = {}
        self.start_time = time.time()
    
    def run_tests(
        self,
        test_type: str = "all",
        environment: str = "local",
        coverage: bool = True,
        parallel: int = 1,
        verbose: bool = False,
        fail_fast: bool = False,
        markers: Optional[List[str]] = None,
        output_format: str = "term"
    ) -> int:
        """
        Run tests with specified configuration.
        
        Args:
            test_type: Type of tests to run ("all", "unit", "integration", "e2e", etc.)
            environment: Test environment ("local", "docker", "ci", "isolated")
            coverage: Enable coverage reporting
            parallel: Number of parallel workers
            verbose: Enable verbose output
            fail_fast: Stop on first failure
            markers: Additional pytest markers
            output_format: Output format ("term", "json", "html")
            
        Returns:
            int: Exit code (0 for success, non-zero for failure)
        """
        print(f"🚀 Starting Heimdall test run...")
        print(f"   Test type: {test_type}")
        print(f"   Environment: {environment}")
        print(f"   Coverage: {'enabled' if coverage else 'disabled'}")
        print(f"   Parallel workers: {parallel}")
        print("")
        
        # Set up test environment
        with test_environment(environment) as env_settings:
            return self._execute_tests(
                test_type=test_type,
                coverage=coverage,
                parallel=parallel,
                verbose=verbose,
                fail_fast=fail_fast,
                markers=markers,
                output_format=output_format,
                env_settings=env_settings
            )
    
    def _execute_tests(
        self,
        test_type: str,
        coverage: bool,
        parallel: int,
        verbose: bool,
        fail_fast: bool,
        markers: Optional[List[str]],
        output_format: str,
        env_settings: Any
    ) -> int:
        """Execute the actual test run."""
        
        # Build pytest command
        cmd = ["python", "-m", "pytest"]
        
        # Add test selection based on type
        if test_type == "unit":
            cmd.extend(["-m", "unit and not (integration or aws or docker)"])
        elif test_type == "integration":
            cmd.extend(["-m", "integration"])
        elif test_type == "e2e":
            cmd.extend(["-m", "e2e"])
        elif test_type == "starknet":
            cmd.extend(["-m", "starknet"])
        elif test_type == "crypto":
            cmd.extend(["-m", "crypto"])
        elif test_type == "aws":
            cmd.extend(["-m", "aws"])
        elif test_type == "performance":
            cmd.extend(["-m", "slow or performance"])
        elif test_type == "security":
            cmd.extend(["-m", "security"])
        elif test_type != "all":
            # Custom marker or path
            if test_type.startswith("tests/"):
                cmd.append(test_type)
            else:
                cmd.extend(["-m", test_type])
        
        # Add additional markers
        if markers:
            for marker in markers:
                cmd.extend(["-m", marker])
        
        # Add coverage options
        if coverage:
            cmd.extend([
                "--cov=nitro_wallet",
                "--cov=application", 
                "--cov=config",
                "--cov-report=term-missing:skip-covered",
                "--cov-report=html:htmlcov",
                "--cov-report=xml:coverage.xml",
            ])
            
            # Set coverage threshold based on test type
            if test_type in ["unit", "all"]:
                cmd.extend(["--cov-fail-under=80"])
            else:
                cmd.extend(["--cov-fail-under=60"])  # Lower threshold for integration tests
        
        # Add output options
        cmd.extend(["--junitxml=junit.xml"])
        
        if output_format == "json":
            cmd.extend(["--json-report", "--json-report-file=test-report.json"])
        
        if verbose:
            cmd.append("-v")
        else:
            cmd.extend(["--tb=short"])
        
        if fail_fast:
            cmd.append("-x")
        
        # Add parallel execution
        if parallel > 1:
            cmd.extend(["-n", str(parallel)])
        
        # Add test discovery options
        cmd.extend([
            "--strict-markers",
            "--strict-config"
        ])
        
        print(f"📋 Executing: {' '.join(cmd)}")
        print("")
        
        # Execute tests
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                env=self._get_test_environment(),
                timeout=1800  # 30 minutes timeout
            )
            
            exit_code = result.returncode
            
            # Generate summary report
            self._generate_summary_report(exit_code, test_type, coverage)
            
            return exit_code
        
        except subprocess.TimeoutExpired:
            print("❌ Tests timed out after 30 minutes")
            return 1
        
        except KeyboardInterrupt:
            print("\n⚠️  Tests interrupted by user")
            return 130
        
        finally:
            # Cleanup test resources
            self._cleanup_test_resources()
    
    def _get_test_environment(self) -> Dict[str, str]:
        """Get environment variables for test execution."""
        env = os.environ.copy()
        
        # Set Python path
        env["PYTHONPATH"] = str(self.project_root)
        
        # Ensure UTF-8 encoding
        env["PYTHONIOENCODING"] = "utf-8"
        
        # Set test mode
        env["TEST_MODE"] = "true"
        
        return env
    
    def _cleanup_test_resources(self):
        """Clean up test resources."""
        try:
            cleanup_all_test_resources()
            print("🧹 Cleaned up test resources")
        except Exception as e:
            print(f"⚠️  Warning: Failed to cleanup test resources: {e}")
    
    def _generate_summary_report(self, exit_code: int, test_type: str, coverage: bool):
        """Generate a summary report of the test run."""
        duration = time.time() - self.start_time
        
        print("\n" + "="*60)
        print(f"📊 TEST SUMMARY")
        print("="*60)
        print(f"Test Type: {test_type}")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Exit Code: {exit_code}")
        print(f"Result: {'✅ PASSED' if exit_code == 0 else '❌ FAILED'}")
        
        if coverage and exit_code == 0:
            print(f"Coverage Report: htmlcov/index.html")
            print(f"JUnit Report: junit.xml")
        
        print("="*60)
        
        # Show next steps based on result
        if exit_code == 0:
            print("🎉 All tests passed! Next steps:")
            print("   • Review coverage report: open htmlcov/index.html")
            print("   • Run integration tests: make test-integration")
            print("   • Run security scan: make security-scan")
        else:
            print("🔧 Tests failed. Debugging steps:")
            print("   • Check test output above for details")
            print("   • Run with -v for verbose output")
            print("   • Run specific test: pytest tests/path/to/test.py::test_name")
            print("   • Check logs: make local-logs")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Enhanced test runner for Heimdall",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Run all tests with default settings
  %(prog)s --type unit              # Run only unit tests
  %(prog)s --type integration --env docker    # Run integration tests in Docker
  %(prog)s --type starknet --verbose          # Run Starknet tests with verbose output
  %(prog)s --parallel 4 --fail-fast           # Run with 4 workers, stop on first failure
  %(prog)s --no-coverage --type performance   # Run performance tests without coverage
        """
    )
    
    parser.add_argument(
        "--type", "-t",
        choices=["all", "unit", "integration", "e2e", "starknet", "crypto", "aws", "performance", "security"],
        default="all",
        help="Type of tests to run"
    )
    
    parser.add_argument(
        "--environment", "--env", "-e",
        choices=["local", "docker", "ci", "isolated"],
        default="local",
        help="Test environment to use"
    )
    
    parser.add_argument(
        "--no-coverage",
        action="store_true",
        help="Disable coverage reporting"
    )
    
    parser.add_argument(
        "--parallel", "-j",
        type=int,
        default=1,
        help="Number of parallel test workers"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--fail-fast", "-x",
        action="store_true",
        help="Stop on first failure"
    )
    
    parser.add_argument(
        "--marker", "-m",
        action="append",
        help="Additional pytest markers (can be used multiple times)"
    )
    
    parser.add_argument(
        "--output-format",
        choices=["term", "json", "html"],
        default="term",
        help="Output format for test results"
    )
    
    args = parser.parse_args()
    
    # Create and run test runner
    runner = TestRunner()
    
    exit_code = runner.run_tests(
        test_type=args.type,
        environment=args.environment,
        coverage=not args.no_coverage,
        parallel=args.parallel,
        verbose=args.verbose,
        fail_fast=args.fail_fast,
        markers=args.marker,
        output_format=args.output_format
    )
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()