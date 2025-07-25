"""Factory classes for generating multi-user Starknet test data.

This module provides factory classes specifically designed for testing multi-user
scenarios in the Starknet key derivation system, including user isolation, 
concurrent access patterns, and scalability testing.
"""

import base64
import json
import random
import secrets
import string
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

import factory
from factory import fuzzy

from tests.starknet_factories import (
    StarknetPrivateKeyFactory,
    StarknetAddressFactory,
    StarknetFieldElementFactory,
    StarknetInvokeTransactionFactory,
    STARK_PRIME,
    STARK_ORDER
)


class UserIdentityFactory(factory.Factory):
    """Factory for generating unique user identities for multi-user testing."""
    
    class Meta:
        model = dict
    
    user_id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    username = factory.Sequence(lambda n: f"starknet_user_{n:06d}")
    email = factory.LazyAttribute(lambda obj: f"{obj.username}@testdomain.com")
    
    # User classification for testing different scenarios
    user_type = fuzzy.FuzzyChoice([
        'regular',      # Standard user
        'premium',      # High-volume user
        'enterprise',   # Enterprise user with multiple keys
        'test_user'     # Test/development user
    ])
    
    # Session identifiers
    session_id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    client_ip = factory.LazyFunction(
        lambda: f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    )
    
    # Timestamps for session management
    created_at = factory.LazyFunction(lambda: int(time.time()))
    last_active = factory.LazyFunction(lambda: int(time.time()))


class StarknetUserKeyFactory(factory.Factory):
    """Factory for generating user-specific Starknet keys with metadata."""
    
    class Meta:
        model = dict
    
    user_identity = factory.SubFactory(UserIdentityFactory)
    private_key = factory.SubFactory(StarknetPrivateKeyFactory)
    account_address = factory.SubFactory(StarknetAddressFactory)
    
    # Key derivation metadata
    key_index = fuzzy.FuzzyInteger(0, 2**31 - 1)  # BIP32-style key index
    derivation_path = factory.LazyAttribute(
        lambda obj: f"m/44'/60'/0'/0/{obj.key_index}"
    )
    
    # Key management metadata
    key_name = factory.Sequence(lambda n: f"stark_key_{n}")
    created_timestamp = factory.LazyFunction(lambda: int(time.time()))
    last_used = factory.LazyFunction(lambda: int(time.time()))
    usage_count = fuzzy.FuzzyInteger(0, 1000)
    
    # Key status and permissions
    is_active = True
    permissions = factory.LazyFunction(
        lambda: random.sample(['sign', 'derive', 'export'], k=random.randint(1, 3))
    )


class MultiUserSessionFactory(factory.Factory):
    """Factory for generating multi-user session scenarios."""
    
    class Meta:
        model = dict
    
    session_id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    users = factory.LazyFunction(
        lambda: [UserIdentityFactory() for _ in range(random.randint(2, 10))]
    )
    
    # Session configuration
    max_concurrent_users = fuzzy.FuzzyInteger(1, 50)
    session_timeout = fuzzy.FuzzyInteger(300, 3600)  # 5 minutes to 1 hour
    
    # Resource limits per session
    max_keys_per_user = fuzzy.FuzzyInteger(1, 100)
    max_transactions_per_minute = fuzzy.FuzzyInteger(1, 1000)
    
    # Security settings
    require_multi_factor = fuzzy.FuzzyChoice([True, False])
    ip_whitelist = factory.LazyFunction(
        lambda: [f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}" 
                for _ in range(random.randint(1, 5))]
    )


class ConcurrentUserScenarioFactory(factory.Factory):
    """Factory for generating concurrent user access scenarios."""
    
    class Meta:
        model = dict
    
    scenario_id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    user_count = fuzzy.FuzzyInteger(2, 100)
    
    # Concurrency patterns
    access_pattern = fuzzy.FuzzyChoice([
        'simultaneous',  # All users access at the same time
        'staggered',     # Users access with delays
        'burst',         # Rapid succession of accesses
        'sustained'      # Long-running concurrent access
    ])
    
    # Timing configuration
    duration_seconds = fuzzy.FuzzyInteger(1, 300)
    delay_between_users_ms = fuzzy.FuzzyInteger(0, 1000)
    
    # Operations per user
    operations_per_user = fuzzy.FuzzyInteger(1, 50)
    operation_types = factory.LazyFunction(
        lambda: random.sample(['key_derive', 'sign_tx', 'get_address'], 
                             k=random.randint(1, 3))
    )


class StarknetMultiUserTransactionBatch(factory.Factory):
    """Factory for generating batches of transactions from multiple users."""
    
    class Meta:
        model = dict
    
    batch_id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    user_transactions = factory.LazyFunction(
        lambda: {
            str(uuid.uuid4()): {
                'user': UserIdentityFactory(),
                'transactions': [StarknetInvokeTransactionFactory() 
                               for _ in range(random.randint(1, 10))]
            }
            for _ in range(random.randint(2, 20))
        }
    )
    
    # Batch processing metadata
    created_at = factory.LazyFunction(lambda: int(time.time()))
    priority = fuzzy.FuzzyChoice(['low', 'normal', 'high', 'critical'])
    estimated_processing_time = fuzzy.FuzzyInteger(1, 3600)  # seconds


class StarknetUserIsolationTestCase(factory.Factory):
    """Factory for generating user isolation test scenarios."""
    
    class Meta:
        model = dict
    
    test_id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    primary_user = factory.SubFactory(UserIdentityFactory)
    target_user = factory.SubFactory(UserIdentityFactory)
    
    # Test configuration
    isolation_type = fuzzy.FuzzyChoice([
        'memory_isolation',
        'key_isolation', 
        'transaction_isolation',
        'session_isolation'
    ])
    
    # Attack simulation parameters
    attack_vectors = factory.LazyFunction(
        lambda: random.sample([
            'memory_inspection',
            'timing_attack',
            'side_channel',
            'brute_force_access'
        ], k=random.randint(1, 4))
    )
    
    expected_isolation_level = fuzzy.FuzzyChoice([
        'complete',     # No information leakage
        'statistical',  # Minimal statistical leakage acceptable
        'timing'        # Only timing information may leak
    ])


class PerformanceBenchmarkFactory(factory.Factory):
    """Factory for generating performance benchmark test scenarios."""
    
    class Meta:
        model = dict
    
    benchmark_id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    benchmark_type = fuzzy.FuzzyChoice([
        'key_derivation_speed',
        'concurrent_user_capacity',
        'memory_usage_scaling',
        'transaction_throughput'
    ])
    
    # Test parameters
    user_counts = factory.LazyFunction(
        lambda: [2**i for i in range(1, 8)]  # Powers of 2: 2, 4, 8, 16, 32, 64, 128
    )
    
    iterations_per_test = fuzzy.FuzzyInteger(10, 1000)
    warmup_iterations = fuzzy.FuzzyInteger(5, 50)
    
    # Performance thresholds
    max_response_time_ms = fuzzy.FuzzyInteger(100, 5000)
    max_memory_usage_mb = fuzzy.FuzzyInteger(100, 2048)
    min_throughput_ops_per_sec = fuzzy.FuzzyInteger(1, 1000)
    
    # Resource monitoring
    monitor_cpu = True
    monitor_memory = True
    monitor_network = fuzzy.FuzzyChoice([True, False])
    monitor_disk_io = fuzzy.FuzzyChoice([True, False])


class SecurityValidationScenarioFactory(factory.Factory):
    """Factory for generating security validation test scenarios."""
    
    class Meta:
        model = dict
    
    scenario_id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    security_test_type = fuzzy.FuzzyChoice([
        'key_entropy_validation',
        'cryptographic_correctness',
        'side_channel_resistance',
        'memory_leak_detection',
        'access_control_validation'
    ])
    
    # Test configuration
    test_duration_seconds = fuzzy.FuzzyInteger(10, 300)
    sample_size = fuzzy.FuzzyInteger(100, 10000)
    
    # Security parameters
    entropy_threshold_bits = fuzzy.FuzzyInteger(200, 256)
    timing_variation_threshold_ns = fuzzy.FuzzyInteger(1000, 100000)
    memory_leak_threshold_bytes = fuzzy.FuzzyInteger(1024, 1048576)  # 1KB to 1MB
    
    # Attack simulation
    simulate_attacks = factory.LazyFunction(
        lambda: random.sample([
            'timing_attack',
            'power_analysis',
            'fault_injection',
            'cache_timing',
            'branch_prediction'
        ], k=random.randint(1, 3))
    )


# Utility functions for creating complex multi-user test scenarios

def create_multi_user_key_derivation_scenario(user_count: int = 10) -> Dict:
    """Create a complete multi-user key derivation test scenario.
    
    Args:
        user_count: Number of users to include in the scenario
        
    Returns:
        Dict containing complete multi-user scenario data
    """
    users = [UserIdentityFactory() for _ in range(user_count)]
    user_keys = {
        user['user_id']: [StarknetUserKeyFactory(user_identity=user) 
                         for _ in range(random.randint(1, 5))]
        for user in users
    }
    
    return {
        'scenario_id': str(uuid.uuid4()),
        'users': users,
        'user_keys': user_keys,
        'session': MultiUserSessionFactory(users=users),
        'concurrent_scenario': ConcurrentUserScenarioFactory(user_count=user_count),
        'created_at': int(time.time())
    }


def create_isolation_test_matrix() -> List[Dict]:
    """Create a comprehensive matrix of isolation test scenarios.
    
    Returns:
        List of isolation test scenarios covering different attack vectors
    """
    isolation_types = ['memory_isolation', 'key_isolation', 'transaction_isolation', 'session_isolation']
    attack_vectors = ['memory_inspection', 'timing_attack', 'side_channel', 'brute_force_access']
    
    test_matrix = []
    for isolation_type in isolation_types:
        for attack_vector in attack_vectors:
            test_case = StarknetUserIsolationTestCase(
                isolation_type=isolation_type,
                attack_vectors=[attack_vector]
            )
            test_matrix.append(test_case)
    
    return test_matrix


def create_performance_test_suite() -> Dict:
    """Create a comprehensive performance test suite.
    
    Returns:
        Dict containing various performance benchmark scenarios
    """
    benchmark_types = [
        'key_derivation_speed',
        'concurrent_user_capacity', 
        'memory_usage_scaling',
        'transaction_throughput'
    ]
    
    benchmarks = {}
    for benchmark_type in benchmark_types:
        benchmarks[benchmark_type] = PerformanceBenchmarkFactory(
            benchmark_type=benchmark_type
        )
    
    return {
        'suite_id': str(uuid.uuid4()),
        'benchmarks': benchmarks,
        'created_at': int(time.time()),
        'estimated_duration_minutes': sum(
            benchmark['iterations_per_test'] * len(benchmark['user_counts']) / 60
            for benchmark in benchmarks.values()
        )
    }


def create_concurrent_user_load_test(peak_users: int = 100, ramp_up_seconds: int = 30) -> Dict:
    """Create a concurrent user load test scenario.
    
    Args:
        peak_users: Maximum number of concurrent users
        ramp_up_seconds: Time to ramp up to peak users
        
    Returns:
        Dict containing load test configuration
    """
    # Calculate user ramp-up schedule
    users_per_second = peak_users / ramp_up_seconds
    ramp_schedule = []
    
    for second in range(ramp_up_seconds):
        users_at_second = int(users_per_second * (second + 1))
        ramp_schedule.append({
            'timestamp': second,
            'active_users': users_at_second,
            'new_users': max(0, users_at_second - (ramp_schedule[-1]['active_users'] if ramp_schedule else 0))
        })
    
    return {
        'load_test_id': str(uuid.uuid4()),
        'peak_users': peak_users,
        'ramp_up_seconds': ramp_up_seconds,
        'ramp_schedule': ramp_schedule,
        'user_scenarios': [
            ConcurrentUserScenarioFactory() for _ in range(peak_users)
        ],
        'monitoring_config': {
            'sample_interval_seconds': 1,
            'metrics': ['response_time', 'throughput', 'error_rate', 'memory_usage', 'cpu_usage']
        }
    }


def create_security_validation_suite() -> Dict:
    """Create a comprehensive security validation test suite.
    
    Returns:
        Dict containing various security validation scenarios
    """
    security_tests = [
        'key_entropy_validation',
        'cryptographic_correctness',
        'side_channel_resistance', 
        'memory_leak_detection',
        'access_control_validation'
    ]
    
    test_scenarios = {}
    for test_type in security_tests:
        test_scenarios[test_type] = SecurityValidationScenarioFactory(
            security_test_type=test_type
        )
    
    return {
        'suite_id': str(uuid.uuid4()),
        'security_tests': test_scenarios,
        'compliance_requirements': [
            'FIPS_140_2_Level_3',
            'Common_Criteria_EAL4',
            'SOC2_Type2'
        ],
        'created_at': int(time.time())
    }


def create_memory_cleanup_test_scenario(user_count: int = 50) -> Dict:
    """Create a test scenario specifically for memory cleanup validation.
    
    Args:
        user_count: Number of users to simulate for memory cleanup testing
        
    Returns:
        Dict containing memory cleanup test configuration
    """
    return {
        'test_id': str(uuid.uuid4()),
        'user_count': user_count,
        'users': [UserIdentityFactory() for _ in range(user_count)],
        'test_phases': [
            {
                'phase': 'memory_baseline',
                'duration_seconds': 30,
                'operations': []
            },
            {
                'phase': 'key_generation_load',
                'duration_seconds': 120,
                'operations': ['generate_keys', 'derive_addresses']
            },
            {
                'phase': 'transaction_signing_load', 
                'duration_seconds': 180,
                'operations': ['sign_transactions', 'validate_signatures']
            },
            {
                'phase': 'cleanup_validation',
                'duration_seconds': 60,
                'operations': ['force_gc', 'validate_memory_cleanup']
            }
        ],
        'memory_thresholds': {
            'max_growth_percentage': 150,  # 50% growth allowed
            'cleanup_efficiency_percentage': 90,  # 90% of allocated memory should be freed
            'leak_detection_threshold_bytes': 10485760  # 10MB leak threshold
        },
        'monitoring_interval_seconds': 1
    }


# Test data validation utilities

def validate_user_isolation(user1_data: Dict, user2_data: Dict) -> bool:
    """Validate that two users' data doesn't overlap inappropriately.
    
    Args:
        user1_data: First user's test data
        user2_data: Second user's test data
        
    Returns:
        bool: True if users are properly isolated
    """
    # Check that user IDs are different
    if user1_data.get('user_id') == user2_data.get('user_id'):
        return False
    
    # Check that private keys are different
    if user1_data.get('private_key') == user2_data.get('private_key'):
        return False
    
    # Check that session IDs are different
    if user1_data.get('session_id') == user2_data.get('session_id'):
        return False
    
    return True


def estimate_test_duration(test_scenario: Dict) -> int:
    """Estimate the duration of a test scenario in seconds.
    
    Args:
        test_scenario: Test scenario configuration
        
    Returns:
        int: Estimated duration in seconds
    """
    base_duration = 0
    
    if 'user_count' in test_scenario:
        # Estimate based on user count (more users = longer test)
        base_duration += test_scenario['user_count'] * 2
    
    if 'iterations_per_test' in test_scenario:
        # Add time for iterations
        base_duration += test_scenario['iterations_per_test'] * 0.1
    
    if 'duration_seconds' in test_scenario:
        # Use explicit duration if provided
        base_duration = max(base_duration, test_scenario['duration_seconds'])
    
    return max(base_duration, 10)  # Minimum 10 seconds


def generate_test_report_metadata(test_results: List[Dict]) -> Dict:
    """Generate metadata for test result reporting.
    
    Args:
        test_results: List of test result dictionaries
        
    Returns:
        Dict containing test report metadata
    """
    return {
        'report_id': str(uuid.uuid4()),
        'generated_at': int(time.time()),
        'total_tests': len(test_results),
        'passed_tests': sum(1 for result in test_results if result.get('passed', False)),
        'failed_tests': sum(1 for result in test_results if not result.get('passed', True)),
        'total_users_tested': sum(result.get('user_count', 0) for result in test_results),
        'total_duration_seconds': sum(result.get('duration_seconds', 0) for result in test_results),
        'performance_metrics': {
            'avg_response_time_ms': sum(result.get('avg_response_time_ms', 0) for result in test_results) / len(test_results) if test_results else 0,
            'max_concurrent_users': max((result.get('concurrent_users', 0) for result in test_results), default=0),
            'total_transactions_processed': sum(result.get('transactions_processed', 0) for result in test_results)
        }
    }