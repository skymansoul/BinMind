

import os
import tempfile
import unittest# -*- coding: utf-8 -*-

import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestVulDBWithMocks(unittest.TestCase):

    def test_vuldb_api_key_from_environ(self):
        original_key = os.environ.get('VULDB_API_KEY', '')

        os.environ['VULDB_API_KEY'] = 'test-vuldb-api-key-1234567890'

        try:
            import importlib
            import config
            importlib.reload(config)

            self.assertEqual(config.Config.VULDB_API_KEY, 'test-vuldb-api-key-1234567890')
        finally:
            if original_key:
                os.environ['VULDB_API_KEY'] = original_key
            else:
                os.environ.pop('VULDB_API_KEY', None)
            import importlib
            import config
            importlib.reload(config)

    def test_github_token_from_environ(self):
        original_token = os.environ.get('GITHUB_TOKEN', '')

        os.environ['GITHUB_TOKEN'] = 'test-github-token-1234567890'

        try:
            import importlib
            import config
            importlib.reload(config)

            self.assertEqual(config.Config.GITHUB_TOKEN, 'test-github-token-1234567890')
        finally:
            if original_token:
                os.environ['GITHUB_TOKEN'] = original_token
            else:
                os.environ.pop('GITHUB_TOKEN', None)
            import importlib
            import config
            importlib.reload(config)

    def test_mask_sensitive_data_vuldb_key(self):
        from config import mask_sensitive_data

        test_text = 'VULDB_API_KEY=abcdef1234567890secret'
        masked = mask_sensitive_data(test_text)

        self.assertIn('MASKED', masked)
        self.assertNotIn('abcdef1234567890secret', masked)

    def test_mask_sensitive_data_github_token(self):
        from config import mask_sensitive_data

        test_text = 'GITHUB_TOKEN=ghp_abcdef1234567890secret'
        masked = mask_sensitive_data(test_text)

        self.assertIn('MASKED', masked)

    def test_process_vuldb_entry_full(self):
        from modules.vuln.vuln_db import VulnerabilityDatabase

        temp_db = tempfile.mktemp(suffix='.db')
        db = VulnerabilityDatabase(temp_db)

        full_entry = {
            'source': {
                'id': '99999',
                'cve': {'id': 'CVE-2024-99999'},
                'title': 'Full Test Vulnerability',
                'advisory': 'This is a full test vulnerability with CVSS score',
                'risk': {'name': 'Critical'},
                'cvss': {'score': 9.8},
                'vuldb_link': 'https://vuldb.com/?id.99999',
                'date': {'last_modified': '2024-01-15T10:30:00Z'},
                'product': {
                    'vendor': {'name': 'TestVendor'},
                    'name': 'TestProduct',
                    'version': '1.0.0'
                }
            }
        }

        result = db._process_vuldb_entry(full_entry)

        self.assertIsNotNone(result)
        self.assertEqual(result['vuln_id'], '99999')
        self.assertEqual(result['source'], 'VulDB')
        self.assertEqual(result['severity'], 'Critical')
        self.assertEqual(result['cvss_score'], 9.8)
        self.assertIn('CVE-2024-99999', result['cve_ids'])
        self.assertEqual(result['description'], 'This is a full test vulnerability with CVSS score')

        db.close()
        if os.path.exists(temp_db):
            os.remove(temp_db)

    def test_process_vuldb_entry_minimal(self):
        from modules.vuln.vuln_db import VulnerabilityDatabase

        temp_db = tempfile.mktemp(suffix='.db')
        db = VulnerabilityDatabase(temp_db)

        minimal_entry = {
            'source': {
                'id': '11111',
                'title': 'Minimal Vulnerability'
            }
        }

        result = db._process_vuldb_entry(minimal_entry)

        self.assertIsNotNone(result)
        self.assertEqual(result['vuln_id'], '11111')
        self.assertEqual(result['severity'], 'Unknown')
        self.assertIn(result['cvss_score'], [0.0, None, 0])
        self.assertEqual(result['cve_ids'], [])

        db.close()
        if os.path.exists(temp_db):
            os.remove(temp_db)


if __name__ == '__main__':
    unittest.main()
