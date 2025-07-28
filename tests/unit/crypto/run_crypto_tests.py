#!/usr/bin/env python3
"""
Comprehensive test runner for all cryptographic operation tests.

This script provides a centralized way to run all cryptographic tests
with various options and reporting capabilities.
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Dict, Any


def run_command(cmd: List[str], description: str) -> Dict[str, Any]:
    """Run a command and return results."""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'='*60}")
    
    start_time = time.time()
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent.parent  # Project root
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"Exit code: {result.returncode}")
        print(f"Duration: {duration:.2f} seconds")
        
        if result.stdout:
            print(f"\nSTDOUT:\n{result.stdout}")
        
        if result.stderr:
            print(f"\nSTDERR:\n{result.stderr}")
        
        return {
            'success': result.returncode == 0,
            'duration': duration,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
        
    except Exception as e:
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"Error running command: {e}")
        return {
            'success': False,
            'duration': duration,
            'stdout': '',
            'stderr': str(e),
            'returncode': -1
        }


def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(
        description="Run comprehensive cryptographic operation tests"
    )
    
    parser.add_argument(
        '--test-type',
        choices=['all', 'unit', 'fast', 'slow', 'security', 'performance'],
        default='all',
        help='Type of tests to run'
    )
    
    parser.add_argument(
        '--coverage',
        action='store_true',
        help='Run tests with coverage reporting'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Run tests with verbose output'
    )
    
    parser.add_argument(
        '--parallel',
        type=int,
        default=1,
        help='Number of parallel test processes'
    )
    
    parser.add_argument(
        '--specific-test',
        help='Run a specific test file or test function'
    )
    
    parser.add_argument(
        '--output-format',
        choices=['console', 'junit', 'html'],
        default='console',
        help='Test output format'
    )
    
    args = parser.parse_args()
    
    # Base pytest command
    pytest_cmd = ['python', '-m', 'pytest']
    
    # Add verbosity
    if args.verbose:
        pytest_cmd.extend(['-v', '-s'])
    
    # Add coverage if requested
    if args.coverage:
        pytest_cmd.extend([
            '--cov=application.starknet.enclave',
            '--cov-report=term-missing',
            '--cov-report=html:htmlcov',
            '--cov-report=xml:coverage.xml'
        ])
    
    # Add parallel execution
    if args.parallel > 1:
        pytest_cmd.extend(['-n', str(args.parallel)])
    
    # Add output format
    if args.output_format == 'junit':
        pytest_cmd.extend(['--junit-xml=test_results.xml'])
    elif args.output_format == 'html':
        pytest_cmd.extend(['--html=test_report.html', '--self-contained-html'])
    
    # Test configurations based on type
    test_configs = {
        'all': {
            'description': 'All cryptographic tests',
            'paths': ['tests/unit/crypto/'],
            'markers': []
        },
        'unit': {
            'description': 'Unit tests only',
            'paths': ['tests/unit/crypto/'],
            'markers': ['-m', 'not slow']
        },
        'fast': {
            'description': 'Fast tests only',
            'paths': ['tests/unit/crypto/'],
            'markers': ['-m', 'not slow and not performance']
        },
        'slow': {
            'description': 'Slow tests only',
            'paths': ['tests/unit/crypto/'],
            'markers': ['-m', 'slow']
        },
        'security': {
            'description': 'Security-focused tests',
            'paths': ['tests/unit/crypto/test_security_properties.py'],
            'markers': []
        },
        'performance': {
            'description': 'Performance tests',
            'paths': ['tests/unit/crypto/test_performance_edge_cases.py'],
            'markers': []
        }
    }
    
    # Results tracking
    results = {}
    overall_start = time.time()
    
    print("Heimdall Cryptographic Test Suite")
    print("="*60)
    print(f"Test Type: {args.test_type}")
    print(f"Coverage: {'Enabled' if args.coverage else 'Disabled'}")
    print(f"Verbose: {'Enabled' if args.verbose else 'Disabled'}")
    print(f"Parallel: {args.parallel} processes")
    print(f"Output Format: {args.output_format}")
    
    if args.specific_test:
        # Run specific test
        cmd = pytest_cmd + [args.specific_test]
        result = run_command(cmd, f"Specific test: {args.specific_test}")
        results['specific'] = result
    else:
        # Run configured test type
        config = test_configs[args.test_type]
        
        # Build command
        cmd = pytest_cmd + config['paths'] + config['markers']
        
        # Run tests
        result = run_command(cmd, config['description'])
        results[args.test_type] = result
        
        # If running all tests, also run specific test categories
        if args.test_type == 'all':
            print(f"\n{'='*60}")
            print("Running individual test file breakdown...")
            print(f"{'='*60}")
            
            test_files = [
                ('HKDF Implementation', 'tests/unit/crypto/test_hkdf_implementation.py'),
                ('Key Derivation', 'tests/unit/crypto/test_key_derivation.py'),
                ('Starknet Crypto', 'tests/unit/crypto/test_starknet_crypto.py'),
                ('Security Properties', 'tests/unit/crypto/test_security_properties.py'),
                ('AWS Integration', 'tests/unit/crypto/test_aws_integration.py'),
                ('Performance & Edge Cases', 'tests/unit/crypto/test_performance_edge_cases.py')
            ]
            
            for name, path in test_files:
                cmd = pytest_cmd + [path, '-m', 'not slow']
                result = run_command(cmd, f"{name} Tests")
                results[name.lower().replace(' ', '_')] = result
    
    # Final summary
    overall_end = time.time()
    total_duration = overall_end - overall_start
    
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Total Duration: {total_duration:.2f} seconds")
    
    success_count = sum(1 for r in results.values() if r['success'])
    total_count = len(results)
    
    print(f"Test Categories: {success_count}/{total_count} passed")
    
    for category, result in results.items():
        status = "PASS" if result['success'] else "FAIL"
        print(f"  {category:20} : {status:4} ({result['duration']:.2f}s)")
    
    # Overall result
    overall_success = all(r['success'] for r in results.values())
    
    print(f"\nOverall Result: {'PASS' if overall_success else 'FAIL'}")
    
    if not overall_success:
        print("\nFailed test details:")
        for category, result in results.items():
            if not result['success']:
                print(f"\n{category} (exit code {result['returncode']}):")
                if result['stderr']:
                    print(f"  Error: {result['stderr'][:500]}...")
    
    # Coverage summary if enabled
    if args.coverage and overall_success:
        print(f"\n{'='*60}")
        print("COVERAGE SUMMARY")
        print(f"{'='*60}")
        print("Coverage reports generated:")
        print("  - Terminal: (shown above)")
        print("  - HTML: htmlcov/index.html")
        print("  - XML: coverage.xml")
    
    # Performance summary
    if args.test_type in ['all', 'performance']:
        print(f"\n{'='*60}")
        print("PERFORMANCE NOTES")
        print(f"{'='*60}")
        print("Key performance test areas covered:")
        print("  - HKDF implementation speed")
        print("  - Key derivation scalability")
        print("  - Memory usage patterns")
        print("  - Concurrent access performance")
        print("  - Timing attack resistance")
    
    # Security summary
    if args.test_type in ['all', 'security']:
        print(f"\n{'='*60}")
        print("SECURITY TEST COVERAGE")
        print(f"{'='*60}")
        print("Security aspects tested:")
        print("  - Constant-time operations")
        print("  - Timing attack resistance")
        print("  - Cryptographic independence")
        print("  - Memory cleanup")
        print("  - Input validation")
    
    # Exit with appropriate code
    sys.exit(0 if overall_success else 1)


if __name__ == "__main__":
    main()