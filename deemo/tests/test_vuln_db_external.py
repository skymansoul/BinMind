#!/usr/bin/env python3
"""
外部漏洞数据库查询功能单元测试

测试内容:
- VulDB 查询功能
- GitHub Advisory 查询功能
- 缓存机制测试
- 参数验证测试
- 综合查询测试
"""

import os
import sys
import tempfile
import json
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestVulDBExternalQueries(unittest.TestCase):
    
    def setUp(self):
        self.temp_db = tempfile.mktemp(suffix='.db')
        from modules.vuln_db import VulnerabilityDatabase
        self.VulnDB = VulnerabilityDatabase
    
    def tearDown(self):
        if os.path.exists(self.temp_db):
            os.remove(self.temp_db)
    
    def test_validate_external_query_params_valid_cve(self):
        db = self.VulnDB(self.temp_db)
        
        result = db._validate_external_query_params(cve_id='CVE-2024-12345')
        
        self.assertTrue(result['valid'])
        self.assertEqual(result['sanitized']['cve_id'], 'CVE-2024-12345')
        db.close()
    
    def test_validate_external_query_params_invalid_cve(self):
        db = self.VulnDB(self.temp_db)
        
        result = db._validate_external_query_params(cve_id='INVALID-CVE-12345')
        
        self.assertFalse(result['valid'])
        self.assertGreater(len(result['errors']), 0)
        db.close()
    
    def test_validate_external_query_params_package_name(self):
        db = self.VulnDB(self.temp_db)
        
        result = db._validate_external_query_params(package_name='openssl')
        
        self.assertTrue(result['valid'])
        self.assertEqual(result['sanitized']['package_name'], 'openssl')
        db.close()
    
    def test_validate_external_query_params_package_name_sanitized(self):
        db = self.VulnDB(self.temp_db)
        
        result = db._validate_external_query_params(package_name='openssl; rm -rf /')
        
        self.assertTrue(result['valid'])
        self.assertEqual(result['sanitized']['package_name'], 'opensslrm-rf')
        db.close()
    
    def test_validate_external_query_params_binary_path_injection(self):
        db = self.VulnDB(self.temp_db)
        
        result = db._validate_external_query_params(binary_name='../../../etc/passwd')
        
        self.assertFalse(result['valid'])
        db.close()
    
    def test_process_vuldb_entry(self):
        db = self.VulnDB(self.temp_db)
        
        mock_entry = {
            'source': {
                'id': '12345',
                'cve': {'id': 'CVE-2024-12345'},
                'title': 'Test Vulnerability',
                'advisory': 'This is a test vulnerability description',
                'risk': {'name': 'High'},
                'cvss': {'score': 8.5}
            }
        }
        
        result = db._process_vuldb_entry(mock_entry)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['vuln_id'], '12345')
        self.assertEqual(result['source'], 'VulDB')
        self.assertEqual(result['severity'], 'High')
        self.assertEqual(result['cvss_score'], 8.5)
        self.assertIn('CVE-2024-12345', result['cve_ids'])
        db.close()
    
    def test_process_vuldb_entry_none(self):
        db = self.VulnDB(self.temp_db)
        
        result = db._process_vuldb_entry(None)
        self.assertIsNone(result)
        db.close()
    
    def test_process_github_advisory_graphql(self):
        db = self.VulnDB(self.temp_db)
        
        mock_advisory = {
            'ghsaId': 'GHSA-1234-5678-9abc',
            'summary': 'Test GitHub Advisory',
            'description': 'This is a test GitHub advisory',
            'severity': 'CRITICAL',
            'cvss': {'score': 9.8, 'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'},
            'cwes': {'nodes': [{'cweId': 'CWE-123', 'description': 'Buffer Overflow'}]},
            'identifiers': [
                {'type': 'GHSA', 'value': 'GHSA-1234-5678-9abc'},
                {'type': 'CVE', 'value': 'CVE-2024-12345'}
            ],
            'publishedAt': '2024-01-01T00:00:00Z',
            'updatedAt': '2024-01-02T00:00:00Z',
            'references': {'nodes': [{'type': 'WEB', 'url': 'https://example.com'}]},
            'vulnerabilities': {'nodes': [
                {
                    'package': {'name': 'test-package', 'ecosystem': 'NPM'},
                    'vulnerableVersionRange': '< 1.0.0',
                    'patchedVersions': '>= 1.0.0',
                    'firstPatchedVersion': {'identifier': '1.0.0'}
                }
            ]}
        }
        
        result = db._process_github_advisory_graphql(mock_advisory)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['vuln_id'], 'GHSA-1234-5678-9abc')
        self.assertEqual(result['source'], 'GitHub Advisory')
        self.assertEqual(result['severity'], 'CRITICAL')
        self.assertEqual(result['cvss_score'], 9.8)
        self.assertIn('CVE-2024-12345', result['cve_ids'])
        self.assertEqual(len(result['vulnerabilities']), 1)
        db.close()
    
    def test_build_github_advisory_query_ghsa(self):
        db = self.VulnDB(self.temp_db)
        
        query = db._build_github_advisory_query(ghsa_id='GHSA-1234-5678-9abc')
        
        self.assertIn('GHSA-1234-5678-9abc', query)
        self.assertIn('securityAdvisory', query)
        db.close()
    
    def test_build_github_advisory_query_search(self):
        db = self.VulnDB(self.temp_db)
        
        query = db._build_github_advisory_query(package_name='test-package', ecosystem='npm')
        
        self.assertIn('test-package', query)
        self.assertIn('securityAdvisories', query)
        self.assertIn('NPM', query)
        db.close()
    
    def test_extract_github_advisories_from_graphql_single(self):
        db = self.VulnDB(self.temp_db)
        
        mock_data = {
            'data': {
                'securityAdvisory': {
                    'ghsaId': 'GHSA-1234-5678-9abc',
                    'summary': 'Test Advisory'
                }
            }
        }
        
        result = db._extract_github_advisories_from_graphql(mock_data)
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['ghsaId'], 'GHSA-1234-5678-9abc')
        db.close()
    
    def test_extract_github_advisories_from_graphql_list(self):
        db = self.VulnDB(self.temp_db)
        
        mock_data = {
            'data': {
                'securityAdvisories': {
                    'nodes': [
                        {'ghsaId': 'GHSA-1', 'summary': 'Test 1'},
                        {'ghsaId': 'GHSA-2', 'summary': 'Test 2'}
                    ]
                }
            }
        }
        
        result = db._extract_github_advisories_from_graphql(mock_data)
        
        self.assertEqual(len(result), 2)
        db.close()
    
    def test_extract_github_advisories_from_graphql_empty(self):
        db = self.VulnDB(self.temp_db)
        
        result = db._extract_github_advisories_from_graphql({})
        
        self.assertEqual(len(result), 0)
        db.close()
    
    def test_valid_sources(self):
        db = self.VulnDB(self.temp_db)
        
        self.assertIn('all', db.VALID_SOURCES)
        self.assertIn('nvd', db.VALID_SOURCES)
        self.assertIn('vuldb', db.VALID_SOURCES)
        self.assertIn('ghadvisory', db.VALID_SOURCES)
        db.close()
    
    def test_query_all_external_source_validation(self):
        db = self.VulnDB(self.temp_db)
        
        results = db.query_all_external(
            package_name='openssl',
            source='invalid_source',
            use_cache=False
        )
        
        self.assertEqual(results['stats']['requested_source'], 'all')
        db.close()
    
    def test_enhanced_search_similar_with_external_flag(self):
        db = self.VulnDB(self.temp_db)
        
        db.add_vulnerability(
            vulnerability_type='Stack Overflow',
            binary_name='test_binary',
            binary_format='ELF',
            architecture='amd64',
            bits=64,
            function_name='main',
            pseudocode='int main() { char buf[100]; gets(buf); }',
            dangerous_functions=['gets', 'strcpy']
        )
        
        results = db.enhanced_search_similar(
            pseudocode='int main() { gets(buf); }',
            dangerous_functions=['gets'],
            binary_format='ELF',
            architecture='amd64',
            include_external=False,
            limit=10
        )
        
        self.assertIn('local_combined', results)
        self.assertIn('external_data', results)
        self.assertEqual(results['stats']['external_matches'], 0)
        self.assertGreater(len(results['local_combined']), 0)
        db.close()
    
    def test_save_external_cache_with_new_fields(self):
        db = self.VulnDB(self.temp_db)
        
        test_data = [{
            'vuln_id': 'CVE-2024-12345',
            'cve_id': 'CVE-2024-12345',
            'severity': 'High',
            'cvss_score': 8.5,
            'title': 'Test Vulnerability',
            'source': 'Test Source'
        }]
        
        result = db._save_external_cache(
            source='test_source',
            cache_key='test_cache_key',
            data=test_data,
            ttl_seconds=3600
        )
        
        self.assertTrue(result)
        
        cached = db._get_external_cache('test_source', 'test_cache_key')
        self.assertIsNotNone(cached)
        self.assertEqual(len(cached), 1)
        self.assertEqual(cached[0]['vuln_id'], 'CVE-2024-12345')
        db.close()
    
    def test_clear_external_cache(self):
        db = self.VulnDB(self.temp_db)
        
        test_data = [{'vuln_id': 'CVE-2024-12345'}]
        db._save_external_cache('source1', 'key1', test_data)
        db._save_external_cache('source2', 'key2', test_data)
        
        before_count = db._get_external_cache('source1', 'key1')
        self.assertIsNotNone(before_count)
        
        deleted = db.clear_external_cache('source1')
        self.assertGreater(deleted, 0)
        
        after_count = db._get_external_cache('source1', 'key1')
        self.assertIsNone(after_count)
        
        db.close()
    
    def test_clear_external_cache_all(self):
        db = self.VulnDB(self.temp_db)
        
        test_data = [{'vuln_id': 'CVE-2024-12345'}]
        db._save_external_cache('source1', 'key1', test_data)
        db._save_external_cache('source2', 'key2', test_data)
        
        deleted = db.clear_external_cache()
        self.assertGreater(deleted, 0)
        
        db.close()


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
        from modules.vuln_db import VulnerabilityDatabase
        
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
        from modules.vuln_db import VulnerabilityDatabase
        
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
