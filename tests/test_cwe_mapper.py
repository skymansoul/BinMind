# -*- coding: utf-8 -*-

import os
import sys
import unittest
import json
from unittest.mock import patch, mock_open

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.cwe_mapper import CWEMapper, CWEMapping, CWEClassification


class TestCWEMapper(unittest.TestCase):
    """CWE mapper test class"""

    def setUp(self):
        """setup before each test"""
        self.test_dir = os.path.dirname(__file__)
        self.data_dir = os.path.join(self.test_dir, '..', 'data')
        os.makedirs(self.data_dir, exist_ok=True)

    def test_load_default_mappings(self):
        mapper = CWEMapper()

        self.assertGreater(len(mapper.mappings), 0)
        self.assertIn('stack_overflow', mapper.mappings)
        self.assertIn('heap_overflow', mapper.mappings)
        self.assertIn('format_string', mapper.mappings)
        self.assertIn('uaf', mapper.mappings)
        self.assertIn('double_free', mapper.mappings)
        self.assertIn('integer_overflow', mapper.mappings)

    def test_get_cwe_for_vulnerability_exact_match(self):
        mapper = CWEMapper()

        result = mapper.get_cwe_for_vulnerability('stack_overflow')

        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0].cwe_id, 'CWE-121')
        self.assertEqual(result[0].cwe_name, 'Stack-based Buffer Overflow')
        self.assertEqual(result[0].confidence, 1.0)

    def test_get_cwe_for_vulnerability_heap_overflow(self):
        mapper = CWEMapper()

        result = mapper.get_cwe_for_vulnerability('heap_overflow')

        self.assertIsInstance(result, list)
        self.assertEqual(result[0].cwe_id, 'CWE-122')
        self.assertEqual(result[0].cwe_name, 'Heap-based Buffer Overflow')

    def test_get_cwe_for_vulnerability_format_string(self):
        """format string vulnerability mapping"""
        mapper = CWEMapper()

        result = mapper.get_cwe_for_vulnerability('format_string')

        self.assertIsInstance(result, list)
        self.assertEqual(result[0].cwe_id, 'CWE-134')
        self.assertEqual(result[0].cwe_name, 'Uncontrolled Format String')

    def test_get_cwe_for_vulnerability_uaf(self):
        """use-after-free vulnerability mapping"""
        mapper = CWEMapper()

        result = mapper.get_cwe_for_vulnerability('uaf')

        self.assertIsInstance(result, list)
        self.assertEqual(result[0].cwe_id, 'CWE-416')
        self.assertEqual(result[0].cwe_name, 'Use After Free')

    def test_get_cwe_for_vulnerability_double_free(self):
        """double free vulnerability mapping"""
        mapper = CWEMapper()

        result = mapper.get_cwe_for_vulnerability('double_free')

        self.assertIsInstance(result, list)
        self.assertEqual(result[0].cwe_id, 'CWE-415')
        self.assertEqual(result[0].cwe_name, 'Double Free')

    def test_get_cwe_for_vulnerability_integer_overflow(self):
        """integer overflow vulnerability mapping"""
        mapper = CWEMapper()

        result = mapper.get_cwe_for_vulnerability('integer_overflow')

        self.assertIsInstance(result, list)
        self.assertEqual(result[0].cwe_id, 'CWE-190')
        self.assertEqual(result[0].cwe_name, 'Integer Overflow or Wraparound')

    def test_get_cwe_for_vulnerability_fuzzy_match(self):
        """fuzzy match for vulnerability type"""
        mapper = CWEMapper()

        result = mapper.get_cwe_for_vulnerability('buffer overflow on stack')

        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0].cwe_id, 'CWE-121')

    def test_get_cwe_for_vulnerability_fuzzy_match_heap(self):
        """fuzzy match for heap-related vulnerabilities"""
        mapper = CWEMapper()

        result = mapper.get_cwe_for_vulnerability('heap based buffer overflow')

        self.assertIsInstance(result, list)
        self.assertEqual(result[0].cwe_id, 'CWE-122')

    def test_get_cwe_for_vulnerability_unknown(self):
        """unknown vulnerability type"""
        mapper = CWEMapper()

        result = mapper.get_cwe_for_vulnerability('unknown_vulnerability_type')

        self.assertIsInstance(result, list)

    def test_get_top_cwe(self):
        """get best matching CWE"""
        mapper = CWEMapper()

        result = mapper.get_top_cwe('stack_overflow')

        self.assertIsNotNone(result)
        self.assertEqual(result.cwe_id, 'CWE-121')
        self.assertEqual(result.cwe_name, 'Stack-based Buffer Overflow')

    def test_get_top_cwe_none(self):
        """get best matching CWE for unknown type"""
        mapper = CWEMapper()

        result = mapper.get_top_cwe('completely_unknown_vuln_type')

        self.assertIsNone(result)

    def test_get_cwe_details(self):
        """get CWE detailed information"""
        mapper = CWEMapper()

        details = mapper.get_cwe_details('CWE-121')

        self.assertIsNotNone(details)
        self.assertEqual(details.cwe_id, 'CWE-121')
        self.assertEqual(details.cwe_name, 'Stack-based Buffer Overflow')
        self.assertIsInstance(details.keywords, list)
        self.assertIsInstance(details.suggestions, list)
        self.assertIsInstance(details.references, list)

    def test_get_cwe_details_not_found(self):
        """get details for nonexistent CWE"""
        mapper = CWEMapper()

        details = mapper.get_cwe_details('CWE-99999')

        self.assertIsNone(details)

    def test_classify_vulnerabilities(self):
        mapper = CWEMapper()

        vulnerabilities = [
            {'type': 'stack_overflow', 'description': 'test stack overflow'},
            {'type': 'heap_overflow', 'description': 'test heap overflow'},
            {'type': 'unknown_type', 'description': 'unknown vulnerability'}
        ]

        classified = mapper.classify_vulnerabilities(vulnerabilities)

        self.assertEqual(len(classified), 3)
        self.assertEqual(classified[0]['cwe']['id'], 'CWE-121')
        self.assertEqual(classified[1]['cwe']['id'], 'CWE-122')
        self.assertIsNone(classified[2]['cwe'])

    def test_get_all_vulnerability_types(self):
        """get all known vulnerability types"""
        mapper = CWEMapper()

        types = mapper.get_all_vulnerability_types()

        self.assertIsInstance(types, list)
        self.assertGreater(len(types), 0)
        self.assertIn('stack_overflow', types)
        self.assertIn('heap_overflow', types)

    def test_get_all_cwe_ids(self):
        """get all known CWE IDs"""
        mapper = CWEMapper()

        cwe_ids = mapper.get_all_cwe_ids()

        self.assertIsInstance(cwe_ids, list)
        self.assertGreater(len(cwe_ids), 0)
        self.assertIn('CWE-121', cwe_ids)
        self.assertIn('CWE-122', cwe_ids)

    def test_add_custom_mapping(self):
        """add custom mapping"""
        mapper = CWEMapper()
        initial_count = len(mapper.mappings)

        mapper.add_custom_mapping(
            vuln_type='custom_vuln',
            cwe_id='CWE-999',
            cwe_name='Custom Vulnerability',
            description='A custom vulnerability type',
            severity='High',
            keywords=['custom', 'test'],
            suggestions=['Fix it'],
            references=['https://example.com']
        )

        self.assertIn('custom_vuln', mapper.mappings)
        self.assertIn('CWE-999', mapper.cwe_details)

        result = mapper.get_cwe_for_vulnerability('custom_vuln')
        self.assertEqual(result[0].cwe_id, 'CWE-999')
        self.assertEqual(result[0].cwe_name, 'Custom Vulnerability')

    def test_save_mappings(self):
        mapper = CWEMapper()
        test_file = os.path.join(self.data_dir, 'test_cwe_mapping.json')

        mapper.save_mappings(test_file)

        self.assertTrue(os.path.exists(test_file))

        with open(test_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.assertIn('mappings', data)
        self.assertIn('stack_overflow', data['mappings'])

        os.remove(test_file)

    def test_get_cwe_url(self):
        mapper = CWEMapper()

        url = mapper.get_cwe_url('CWE-121')
        self.assertEqual(url, 'https://cwe.mitre.org/data/definitions/121.html')

        url = mapper.get_cwe_url('CWE-122')
        self.assertEqual(url, 'https://cwe.mitre.org/data/definitions/122.html')

    def test_case_insensitive_match(self):
        """case insensitive matching"""
        mapper = CWEMapper()

        result_lower = mapper.get_cwe_for_vulnerability('stack_overflow')
        result_upper = mapper.get_cwe_for_vulnerability('STACK_OVERFLOW')
        result_mixed = mapper.get_cwe_for_vulnerability('Stack_Overflow')

        self.assertEqual(result_lower[0].cwe_id, result_upper[0].cwe_id)
        self.assertEqual(result_lower[0].cwe_id, result_mixed[0].cwe_id)

    def test_keyword_based_fuzzy_match(self):
        mapper = CWEMapper()

        result = mapper.get_cwe_for_vulnerability('strcpy buffer overflow')

        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_empty_vulnerability_type(self):
        mapper = CWEMapper()

        result = mapper.get_cwe_for_vulnerability('')

        self.assertIsInstance(result, list)

    def test_whitespace_only_vulnerability_type(self):
        """whitespace-only vulnerability type"""
        mapper = CWEMapper()

        result = mapper.get_cwe_for_vulnerability('   ')

        self.assertIsInstance(result, list)

    def test_load_mappings_from_custom_file(self):
        """load mappings from custom file"""
        test_file = os.path.join(self.data_dir, 'test_custom_mapping.json')
        custom_data = {
            'mappings': {
                'custom_test_vuln': [
                    {
                        'cwe_id': 'CWE-500',
                        'cwe_name': 'Test Vulnerability',
                        'description': 'Test description',
                        'severity': 'Medium',
                        'keywords': ['test'],
                        'suggestions': ['Fix it'],
                        'references': ['https://example.com']
                    }
                ]
            }
        }

        with open(test_file, 'w') as f:
            json.dump(custom_data, f)

        mapper = CWEMapper(mapping_file=test_file)

        self.assertIn('custom_test_vuln', mapper.mappings)
        result = mapper.get_cwe_for_vulnerability('custom_test_vuln')
        self.assertEqual(result[0].cwe_id, 'CWE-500')

        os.remove(test_file)

    def test_fallback_to_default_mappings(self):
        """fall back to default mappings when custom file doesn't exist"""
        mapper = CWEMapper(mapping_file='/nonexistent/path/cwe_mapping.json')

        self.assertIn('stack_overflow', mapper.mappings)
        self.assertIn('heap_overflow', mapper.mappings)


if __name__ == '__main__':
    unittest.main()
