import os
import sys
import unittest
import json
from unittest.mock import patch, mock_open

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.cwe_mapper import CWEMapper, CWEMapping, CWEClassification


class TestCWEMapper(unittest.TestCase):
    """CWE 映射器测试类"""

    def setUp(self):
        """测试前准备"""
        self.test_dir = os.path.dirname(__file__)
        self.data_dir = os.path.join(self.test_dir, '..', 'data')
        os.makedirs(self.data_dir, exist_ok=True)

    def test_load_default_mappings(self):
        """测试加载默认映射"""
        mapper = CWEMapper()
        
        self.assertGreater(len(mapper.mappings), 0)
        self.assertIn('stack_overflow', mapper.mappings)
        self.assertIn('heap_overflow', mapper.mappings)
        self.assertIn('format_string', mapper.mappings)
        self.assertIn('uaf', mapper.mappings)
        self.assertIn('double_free', mapper.mappings)
        self.assertIn('integer_overflow', mapper.mappings)

    def test_get_cwe_for_vulnerability_exact_match(self):
        """测试精确匹配漏洞类型"""
        mapper = CWEMapper()
        
        result = mapper.get_cwe_for_vulnerability('stack_overflow')
        
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0].cwe_id, 'CWE-121')
        self.assertEqual(result[0].cwe_name, 'Stack-based Buffer Overflow')
        self.assertEqual(result[0].confidence, 1.0)

    def test_get_cwe_for_vulnerability_heap_overflow(self):
        """测试堆溢出漏洞映射"""
        mapper = CWEMapper()
        
        result = mapper.get_cwe_for_vulnerability('heap_overflow')
        
        self.assertIsInstance(result, list)
        self.assertEqual(result[0].cwe_id, 'CWE-122')
        self.assertEqual(result[0].cwe_name, 'Heap-based Buffer Overflow')

    def test_get_cwe_for_vulnerability_format_string(self):
        """测试格式化字符串漏洞映射"""
        mapper = CWEMapper()
        
        result = mapper.get_cwe_for_vulnerability('format_string')
        
        self.assertIsInstance(result, list)
        self.assertEqual(result[0].cwe_id, 'CWE-134')
        self.assertEqual(result[0].cwe_name, 'Uncontrolled Format String')

    def test_get_cwe_for_vulnerability_uaf(self):
        """测试使用后释放漏洞映射"""
        mapper = CWEMapper()
        
        result = mapper.get_cwe_for_vulnerability('uaf')
        
        self.assertIsInstance(result, list)
        self.assertEqual(result[0].cwe_id, 'CWE-416')
        self.assertEqual(result[0].cwe_name, 'Use After Free')

    def test_get_cwe_for_vulnerability_double_free(self):
        """测试双重释放漏洞映射"""
        mapper = CWEMapper()
        
        result = mapper.get_cwe_for_vulnerability('double_free')
        
        self.assertIsInstance(result, list)
        self.assertEqual(result[0].cwe_id, 'CWE-415')
        self.assertEqual(result[0].cwe_name, 'Double Free')

    def test_get_cwe_for_vulnerability_integer_overflow(self):
        """测试整数溢出漏洞映射"""
        mapper = CWEMapper()
        
        result = mapper.get_cwe_for_vulnerability('integer_overflow')
        
        self.assertIsInstance(result, list)
        self.assertEqual(result[0].cwe_id, 'CWE-190')
        self.assertEqual(result[0].cwe_name, 'Integer Overflow or Wraparound')

    def test_get_cwe_for_vulnerability_fuzzy_match(self):
        """测试模糊匹配漏洞类型"""
        mapper = CWEMapper()
        
        result = mapper.get_cwe_for_vulnerability('buffer overflow on stack')
        
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0].cwe_id, 'CWE-121')

    def test_get_cwe_for_vulnerability_fuzzy_match_heap(self):
        """测试模糊匹配堆相关漏洞"""
        mapper = CWEMapper()
        
        result = mapper.get_cwe_for_vulnerability('heap based buffer overflow')
        
        self.assertIsInstance(result, list)
        self.assertEqual(result[0].cwe_id, 'CWE-122')

    def test_get_cwe_for_vulnerability_unknown(self):
        """测试未知漏洞类型"""
        mapper = CWEMapper()
        
        result = mapper.get_cwe_for_vulnerability('unknown_vulnerability_type')
        
        self.assertIsInstance(result, list)

    def test_get_top_cwe(self):
        """测试获取最匹配的 CWE"""
        mapper = CWEMapper()
        
        result = mapper.get_top_cwe('stack_overflow')
        
        self.assertIsNotNone(result)
        self.assertEqual(result.cwe_id, 'CWE-121')
        self.assertEqual(result.cwe_name, 'Stack-based Buffer Overflow')

    def test_get_top_cwe_none(self):
        """测试获取未知漏洞类型的最匹配 CWE"""
        mapper = CWEMapper()
        
        result = mapper.get_top_cwe('completely_unknown_vuln_type')
        
        self.assertIsNone(result)

    def test_get_cwe_details(self):
        """测试获取 CWE 详细信息"""
        mapper = CWEMapper()
        
        details = mapper.get_cwe_details('CWE-121')
        
        self.assertIsNotNone(details)
        self.assertEqual(details.cwe_id, 'CWE-121')
        self.assertEqual(details.cwe_name, 'Stack-based Buffer Overflow')
        self.assertIsInstance(details.keywords, list)
        self.assertIsInstance(details.suggestions, list)
        self.assertIsInstance(details.references, list)

    def test_get_cwe_details_not_found(self):
        """测试获取不存在的 CWE 详细信息"""
        mapper = CWEMapper()
        
        details = mapper.get_cwe_details('CWE-99999')
        
        self.assertIsNone(details)

    def test_classify_vulnerabilities(self):
        """测试分类漏洞列表"""
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
        """测试获取所有已知漏洞类型"""
        mapper = CWEMapper()
        
        types = mapper.get_all_vulnerability_types()
        
        self.assertIsInstance(types, list)
        self.assertGreater(len(types), 0)
        self.assertIn('stack_overflow', types)
        self.assertIn('heap_overflow', types)

    def test_get_all_cwe_ids(self):
        """测试获取所有已知 CWE ID"""
        mapper = CWEMapper()
        
        cwe_ids = mapper.get_all_cwe_ids()
        
        self.assertIsInstance(cwe_ids, list)
        self.assertGreater(len(cwe_ids), 0)
        self.assertIn('CWE-121', cwe_ids)
        self.assertIn('CWE-122', cwe_ids)

    def test_add_custom_mapping(self):
        """测试添加自定义映射"""
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
        """测试保存映射到文件"""
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
        """测试获取 CWE URL"""
        mapper = CWEMapper()
        
        url = mapper.get_cwe_url('CWE-121')
        self.assertEqual(url, 'https://cwe.mitre.org/data/definitions/121.html')
        
        url = mapper.get_cwe_url('CWE-122')
        self.assertEqual(url, 'https://cwe.mitre.org/data/definitions/122.html')

    def test_case_insensitive_match(self):
        """测试大小写不敏感匹配"""
        mapper = CWEMapper()
        
        result_lower = mapper.get_cwe_for_vulnerability('stack_overflow')
        result_upper = mapper.get_cwe_for_vulnerability('STACK_OVERFLOW')
        result_mixed = mapper.get_cwe_for_vulnerability('Stack_Overflow')
        
        self.assertEqual(result_lower[0].cwe_id, result_upper[0].cwe_id)
        self.assertEqual(result_lower[0].cwe_id, result_mixed[0].cwe_id)

    def test_keyword_based_fuzzy_match(self):
        """测试基于关键词的模糊匹配"""
        mapper = CWEMapper()
        
        result = mapper.get_cwe_for_vulnerability('strcpy buffer overflow')
        
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_empty_vulnerability_type(self):
        """测试空漏洞类型"""
        mapper = CWEMapper()
        
        result = mapper.get_cwe_for_vulnerability('')
        
        self.assertIsInstance(result, list)

    def test_whitespace_only_vulnerability_type(self):
        """测试空白字符漏洞类型"""
        mapper = CWEMapper()
        
        result = mapper.get_cwe_for_vulnerability('   ')
        
        self.assertIsInstance(result, list)

    def test_load_mappings_from_custom_file(self):
        """测试从自定义文件加载映射"""
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
        """测试当自定义文件不存在时回退到默认映射"""
        mapper = CWEMapper(mapping_file='/nonexistent/path/cwe_mapping.json')
        
        self.assertIn('stack_overflow', mapper.mappings)
        self.assertIn('heap_overflow', mapper.mappings)


if __name__ == '__main__':
    unittest.main()
