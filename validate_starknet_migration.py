#!/usr/bin/env python3
"""
Standalone validation script for Starknet migration.

This script validates the core functionality of the Starknet migration
without relying on pytest or conflicting dependencies.
"""

import sys
import os
import json
import traceback
from pathlib import Path

# Add test modules to path
sys.path.insert(0, str(Path(__file__).parent / "tests"))
sys.path.insert(0, str(Path(__file__).parent / "application" / "starknet" / "enclave"))

def test_basic_imports():
    """Test that basic imports work."""
    print("🔍 Testing basic imports...")
    try:
        from starknet_factories import (
            StarknetPrivateKeyFactory,
            validate_stark_private_key,
            validate_stark_field_element,
            STARK_PRIME,
            STARK_ORDER
        )
        print("  ✓ starknet_factories imports successfully")
        return True
    except ImportError as e:
        print(f"  ✗ Import failed: {e}")
        return False

def test_starknet_server():
    """Test that Starknet server can be imported."""
    print("🔍 Testing Starknet server import...")
    try:
        import server
        print("  ✓ Starknet server imports successfully")
        print(f"  ✓ Has kms_call: {hasattr(server, 'kms_call')}")
        print(f"  ✓ Has StarkCurveSigner: {hasattr(server, 'StarkCurveSigner')}")
        return True
    except ImportError as e:
        print(f"  ✗ Starknet server import failed: {e}")
        return False

def test_key_generation():
    """Test key generation functionality."""
    print("🔍 Testing key generation...")
    try:
        from starknet_factories import (
            StarknetPrivateKeyFactory,
            validate_stark_private_key,
            STARK_ORDER
        )
        
        # Generate multiple keys
        keys = []
        for i in range(10):
            key = StarknetPrivateKeyFactory()
            keys.append(key)
            
            # Validate key format
            if not isinstance(key, str) or not key.startswith('0x'):
                print(f"  ✗ Key {i} has wrong format: {key}")
                return False
            
            # Validate key range
            key_int = int(key, 16)
            if not (0 < key_int < STARK_ORDER):
                print(f"  ✗ Key {i} out of range: {key_int}")
                return False
            
            # Validate using function
            if not validate_stark_private_key(key):
                print(f"  ✗ Key {i} failed validation: {key}")
                return False
        
        # Check uniqueness
        if len(set(keys)) != len(keys):
            print(f"  ✗ Generated keys are not unique")
            return False
        
        print(f"  ✓ Generated {len(keys)} unique valid keys")
        return True
    except Exception as e:
        print(f"  ✗ Key generation failed: {e}")
        return False

def test_field_validation():
    """Test field element validation."""
    print("🔍 Testing field element validation...")
    try:
        from starknet_factories import validate_stark_field_element, STARK_PRIME
        
        # Test valid elements
        valid_elements = [
            "0x1",
            "0x123", 
            1000,
            STARK_PRIME - 1
        ]
        
        for element in valid_elements:
            if not validate_stark_field_element(element):
                print(f"  ✗ Valid element failed: {element}")
                return False
        
        # Test invalid elements
        invalid_elements = [
            STARK_PRIME,
            STARK_PRIME + 1,
            -1,
            "invalid",
            None
        ]
        
        for element in invalid_elements:
            if validate_stark_field_element(element):
                print(f"  ✗ Invalid element passed: {element}")
                return False
        
        print("  ✓ Field element validation working correctly")
        return True
    except Exception as e:
        print(f"  ✗ Field validation failed: {e}")
        return False

def test_directory_structure():
    """Test that required directories exist."""
    print("🔍 Testing directory structure...")
    try:
        base_path = Path(__file__).parent / "application" / "starknet"
        
        required_dirs = [
            "enclave",
            "lambda",
            "server", 
            "user_data"
        ]
        
        for dir_name in required_dirs:
            dir_path = base_path / dir_name
            if not dir_path.exists():
                print(f"  ✗ Missing directory: {dir_name}")
                return False
        
        print("  ✓ All required directories exist")
        return True
    except Exception as e:
        print(f"  ✗ Directory check failed: {e}")
        return False

def test_required_files():
    """Test that required files exist."""
    print("🔍 Testing required files...")
    try:
        base_path = Path(__file__).parent / "application" / "starknet"
        
        required_files = [
            "enclave/server.py",
            "enclave/requirements.txt",
            "enclave/Dockerfile",
            "lambda/lambda_function.py",
            "server/app.py",
            "server/requirements.txt",
            "user_data/user_data.sh"
        ]
        
        for file_name in required_files:
            file_path = base_path / file_name
            if not file_path.exists():
                print(f"  ✗ Missing file: {file_name}")
                return False
        
        print("  ✓ All required files exist")
        return True
    except Exception as e:
        print(f"  ✗ File check failed: {e}")
        return False

def test_constants():
    """Test that constants are correct."""
    print("🔍 Testing Starknet constants...")
    try:
        from starknet_factories import STARK_PRIME, STARK_ORDER
        
        # Check STARK_PRIME = 2^251 + 17 * 2^192 + 1
        expected_prime = 2**251 + 17 * 2**192 + 1
        if STARK_PRIME != expected_prime:
            print(f"  ✗ STARK_PRIME incorrect: {STARK_PRIME} != {expected_prime}")
            return False
        
        # Check STARK_ORDER is reasonable
        if not (0 < STARK_ORDER < STARK_PRIME):
            print(f"  ✗ STARK_ORDER out of range: {STARK_ORDER}")
            return False
        
        print("  ✓ Constants are correct")
        print(f"    STARK_PRIME: {hex(STARK_PRIME)}")
        print(f"    STARK_ORDER: {hex(STARK_ORDER)}")
        return True
    except Exception as e:
        print(f"  ✗ Constants check failed: {e}")
        return False

def test_migration_completeness():
    """Test migration completeness."""
    print("🔍 Testing migration completeness...")
    try:
        # Check both eth1 and starknet exist
        eth_path = Path(__file__).parent / "application" / "eth1"
        starknet_path = Path(__file__).parent / "application" / "starknet"
        
        if not eth_path.exists():
            print("  ✗ Ethereum application missing")
            return False
        
        if not starknet_path.exists():
            print("  ✗ Starknet application missing")
            return False
        
        # Check that both have similar structure
        common_dirs = ["enclave", "lambda"]
        for app_name, app_path in [("eth1", eth_path), ("starknet", starknet_path)]:
            for dir_name in common_dirs:
                if not (app_path / dir_name).exists():
                    print(f"  ✗ {app_name} missing {dir_name} directory")
                    return False
        
        print("  ✓ Migration appears complete - both applications exist")
        return True
    except Exception as e:
        print(f"  ✗ Migration completeness check failed: {e}")
        return False

def main():
    """Run all validation tests."""
    print("🚀 Starknet Migration Validation")
    print("=" * 50)
    
    tests = [
        test_basic_imports,
        test_constants,
        test_key_generation,
        test_field_validation,
        test_directory_structure,
        test_required_files,
        test_migration_completeness,
        test_starknet_server,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            print()
        except Exception as e:
            print(f"  ✗ Test failed with exception: {e}")
            print(f"  Traceback: {traceback.format_exc()}")
            print()
    
    print("=" * 50)
    print(f"📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Starknet migration is ready.")
        return 0
    else:
        print("❌ Some tests failed. Please review the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())