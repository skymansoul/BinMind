#!/usr/bin/env python3
import os
import sys
import unittest
import argparse


def run_tests(verbosity=2, pattern='test_*.py'):
    test_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(test_dir)
    sys.path.insert(0, project_root)
    
    loader = unittest.TestLoader()
    suite = loader.discover(test_dir, pattern=pattern)
    
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1


def main():
    parser = argparse.ArgumentParser(description='Run unit tests for the binary vulnerability analysis tool')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase output verbosity')
    parser.add_argument('-q', '--quiet', action='store_true', help='Reduce output verbosity')
    parser.add_argument('-p', '--pattern', default='test_*.py', help='Test file pattern (default: test_*.py)')
    parser.add_argument('test', nargs='?', help='Specific test module to run')
    
    args = parser.parse_args()
    
    verbosity = 2
    if args.quiet:
        verbosity = 1
    if args.verbose:
        verbosity = 3
    
    if args.test:
        pattern = args.test
    else:
        pattern = args.pattern
    
    return run_tests(verbosity=verbosity, pattern=pattern)


if __name__ == '__main__':
    sys.exit(main())
