import os
import sys
import tempfile
import json
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestVulnerabilityDatabase(unittest.TestCase):
    
    def setUp(self):
        self.temp_db = tempfile.mktemp(suffix='.db')
        from modules.vuln_db import VulnerabilityDatabase
        self.VulnDB = VulnerabilityDatabase
    
    def tearDown(self):
        if os.path.exists(self.temp_db):
            os.remove(self.temp_db)
    
    def test_init_db(self):
        db = self.VulnDB(self.temp_db)
        self.assertIsNotNone(db.connection)
        self.assertTrue(os.path.exists(self.temp_db))
        db.close()
    
    def test_add_vulnerability(self):
        db = self.VulnDB(self.temp_db)
        
        vuln_id = db.add_vulnerability(
            vulnerability_type='Stack Overflow',
            binary_name='test_binary',
            binary_format='ELF',
            architecture='amd64',
            bits=64,
            function_name='main',
            pseudocode='int main() { char buf[100]; gets(buf); }',
            exploit_script='from pwn import *',
            dangerous_functions=['gets'],
            checksec={'nx': True, 'pie': False},
            symbols={'main': 0x401000},
            severity='Critical',
            description='Buffer overflow in main function'
        )
        
        self.assertIsNotNone(vuln_id)
        self.assertGreater(vuln_id, 0)
        db.close()
    
    def test_get_by_id(self):
        db = self.VulnDB(self.temp_db)
        
        vuln_id = db.add_vulnerability(
            vulnerability_type='Test Vuln',
            binary_name='test',
            binary_format='ELF',
            architecture='amd64',
            bits=64,
            function_name='main'
        )
        
        result = db.get_by_id(vuln_id)
        self.assertIsNotNone(result)
        self.assertEqual(result['vulnerability_type'], 'Test Vuln')
        self.assertEqual(result['binary_name'], 'test')
        db.close()
    
    def test_search_by_function(self):
        db = self.VulnDB(self.temp_db)
        
        db.add_vulnerability(
            vulnerability_type='Vuln1',
            binary_name='test1',
            binary_format='ELF',
            architecture='amd64',
            bits=64,
            function_name='main'
        )
        
        db.add_vulnerability(
            vulnerability_type='Vuln2',
            binary_name='test2',
            binary_format='ELF',
            architecture='amd64',
            bits=64,
            function_name='process_input'
        )
        
        results = db.search_by_function('main')
        self.assertGreater(len(results), 0)
        
        any_main = any('main' in r.get('function_name', '') for r in results)
        self.assertTrue(any_main)
        db.close()
    
    def test_search_by_type(self):
        db = self.VulnDB(self.temp_db)
        
        db.add_vulnerability(
            vulnerability_type='Stack Overflow',
            binary_name='test1',
            binary_format='ELF',
            architecture='amd64',
            bits=64,
            function_name='main'
        )
        
        db.add_vulnerability(
            vulnerability_type='Format String',
            binary_name='test2',
            binary_format='ELF',
            architecture='amd64',
            bits=64,
            function_name='main'
        )
        
        results = db.search_by_vulnerability_type('Stack')
        self.assertGreater(len(results), 0)
        any_match = any('Stack' in r.get('vulnerability_type', '') for r in results)
        self.assertTrue(any_match)
        db.close()
    
    def test_get_all(self):
        db = self.VulnDB(self.temp_db)
        
        for i in range(5):
            db.add_vulnerability(
                vulnerability_type=f'TestVuln{i}',
                binary_name=f'test{i}',
                binary_format='ELF',
                architecture='amd64',
                bits=64,
                function_name='main'
            )
        
        results = db.get_all(limit=10)
        self.assertEqual(len(results), 5)
        db.close()
    
    def test_update_vulnerability(self):
        db = self.VulnDB(self.temp_db)
        
        vuln_id = db.add_vulnerability(
            vulnerability_type='Old Type',
            binary_name='test',
            binary_format='ELF',
            architecture='amd64',
            bits=64,
            function_name='main',
            severity='Medium'
        )
        
        success = db.update_vulnerability(
            vuln_id,
            vulnerability_type='New Type',
            severity='Critical',
            notes='Updated note'
        )
        
        self.assertTrue(success)
        
        updated = db.get_by_id(vuln_id)
        self.assertEqual(updated['vulnerability_type'], 'New Type')
        self.assertEqual(updated['severity'], 'Critical')
        self.assertEqual(updated['notes'], 'Updated note')
        db.close()
    
    def test_delete_vulnerability(self):
        db = self.VulnDB(self.temp_db)
        
        vuln_id = db.add_vulnerability(
            vulnerability_type='ToDelete',
            binary_name='test',
            binary_format='ELF',
            architecture='amd64',
            bits=64,
            function_name='main'
        )
        
        before = db.get_by_id(vuln_id)
        self.assertIsNotNone(before)
        
        success = db.delete_vulnerability(vuln_id)
        self.assertTrue(success)
        
        after = db.get_by_id(vuln_id)
        self.assertIsNone(after)
        db.close()
    
    def test_get_statistics(self):
        db = self.VulnDB(self.temp_db)
        
        db.add_vulnerability(
            vulnerability_type='Stack Overflow',
            binary_name='test1',
            binary_format='ELF',
            architecture='amd64',
            bits=64,
            function_name='main',
            severity='Critical'
        )
        
        db.add_vulnerability(
            vulnerability_type='Format String',
            binary_name='test2',
            binary_format='PE',
            architecture='i386',
            bits=32,
            function_name='main',
            severity='High'
        )
        
        stats = db.get_statistics()
        self.assertIn('total', stats)
        self.assertEqual(stats['total'], 2)
        self.assertIn('by_type', stats)
        self.assertIn('by_format', stats)
        self.assertIn('by_architecture', stats)
        self.assertIn('by_severity', stats)
        db.close()
    
    def test_export_import(self):
        db1 = self.VulnDB(self.temp_db)
        
        db1.add_vulnerability(
            vulnerability_type='ExportTest',
            binary_name='export_test',
            binary_format='ELF',
            architecture='amd64',
            bits=64,
            function_name='main',
            severity='High'
        )
        
        export_path = tempfile.mktemp(suffix='.json')
        success = db1.export_database(export_path)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(export_path))
        
        with open(export_path, 'r') as f:
            data = json.load(f)
        self.assertIn('records', data)
        self.assertEqual(len(data['records']), 1)
        
        temp_db2 = tempfile.mktemp(suffix='.db')
        db2 = self.VulnDB(temp_db2)
        
        imported = db2.import_database(export_path, merge=True)
        self.assertEqual(imported, 1)
        
        all_records = db2.get_all()
        self.assertEqual(len(all_records), 1)
        
        db1.close()
        db2.close()
        
        if os.path.exists(export_path):
            os.remove(export_path)
        if os.path.exists(temp_db2):
            os.remove(temp_db2)
    
    def test_hash_pseudocode(self):
        db = self.VulnDB(self.temp_db)
        
        code1 = "int main() { char buf[100]; gets(buf); }"
        code2 = "int main() { char buf[100];gets(buf);}"
        code3 = "int main() { return 0; }"
        
        hash1 = db._hash_pseudocode(code1)
        hash2 = db._hash_pseudocode(code2)
        hash3 = db._hash_pseudocode(code3)
        
        self.assertEqual(hash1, hash2)
        self.assertNotEqual(hash1, hash3)
        db.close()
    
    def test_search_similar(self):
        db = self.VulnDB(self.temp_db)
        
        db.add_vulnerability(
            vulnerability_type='Vuln1',
            binary_name='test1',
            binary_format='ELF',
            architecture='amd64',
            bits=64,
            function_name='main',
            pseudocode='int main() { gets(buf); }',
            dangerous_functions=['gets', 'strcpy']
        )
        
        db.add_vulnerability(
            vulnerability_type='Vuln2',
            binary_name='test2',
            binary_format='PE',
            architecture='amd64',
            bits=64,
            function_name='process',
            dangerous_functions=['system']
        )
        
        results = db.search_similar(
            pseudocode='int main() { gets(buf); }',
            dangerous_functions=['gets'],
            binary_format='ELF',
            architecture='amd64'
        )
        
        self.assertGreater(len(results), 0)
        db.close()


class TestVulnDbWithMocks(unittest.TestCase):
    
    def test_get_vuln_db_function(self):
        from modules.vuln_db import get_vuln_db, VulnerabilityDatabase
        
        db = get_vuln_db()
        self.assertIsInstance(db, VulnerabilityDatabase)
        db.close()
    
    def test_empty_db_operations(self):
        temp_db = tempfile.mktemp(suffix='.db')
        from modules.vuln_db import VulnerabilityDatabase
        db = VulnerabilityDatabase(temp_db)
        
        self.assertEqual(len(db.get_all()), 0)
        self.assertIsNone(db.get_by_id(999))
        
        stats = db.get_statistics()
        self.assertEqual(stats.get('total', 0), 0)
        
        db.close()
        if os.path.exists(temp_db):
            os.remove(temp_db)


if __name__ == '__main__':
    unittest.main()
