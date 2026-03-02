#!/usr/bin/env python3
"""
Test script for Escher encoder/decoder
Tests encode → decode → compare cycle
"""

import sys
import os
import subprocess

def run_test(test_name, input_file):
    """Run encode/decode test"""
    print(f"\n{'='*60}")
    print(f"Test: {test_name}")
    print(f"{'='*60}")
    
    # Files
    encoded_file = f"{test_name}.escher"
    decoded_file = f"{test_name}.decoded.txt"
    
    # Step 1: Encode
    print(f"\n[1] Encoding {input_file} → {encoded_file}")
    result = subprocess.run([
        'python3', 'escher_codec.py', 'encode',
        input_file, encoded_file
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ FAILED: {result.stderr}")
        return False
    print(f"✅ {result.stdout.strip()}")
    
    # Step 2: Decode
    print(f"\n[2] Decoding {encoded_file} → {decoded_file}")
    result = subprocess.run([
        'python3', 'escher_codec.py', 'decode',
        encoded_file, decoded_file
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ FAILED: {result.stderr}")
        return False
    print(f"✅ {result.stdout.strip()}")
    
    # Step 3: Compare
    print(f"\n[3] Comparing original vs decoded")
    
    with open(input_file, 'r') as f:
        original = normalize_text(f.read())
    
    with open(decoded_file, 'r') as f:
        decoded = normalize_text(f.read())
    
    if original == decoded:
        print("✅ MATCH: Decoded output matches original input")
        return True
    else:
        print("❌ MISMATCH: Decoded output differs from original")
        print("\nOriginal:")
        print(original[:500])
        print("\nDecoded:")
        print(decoded[:500])
        return False

def normalize_text(text):
    """Normalize text for comparison (remove comments, extra whitespace)"""
    lines = []
    for line in text.split('\n'):
        # Remove comments
        if '#' in line:
            line = line[:line.index('#')]
        # Strip whitespace
        line = line.strip()
        if line:
            lines.append(line)
    return '\n'.join(lines)

def main():
    print("Escher Encoder/Decoder Test Suite")
    print("="*60)
    
    # Check if escher_codec.py exists
    if not os.path.exists('escher_codec.py'):
        print("❌ ERROR: escher_codec.py not found")
        sys.exit(1)
    
    # Run tests
    tests = [
        ("test_example", "example.escher.txt")
    ]
    
    results = []
    for test_name, input_file in tests:
        if not os.path.exists(input_file):
            print(f"\n⚠️  SKIP: {input_file} not found")
            continue
        
        success = run_test(test_name, input_file)
        results.append((test_name, success))
    
    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\n{passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed")
        sys.exit(1)

if __name__ == '__main__':
    main()
