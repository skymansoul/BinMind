# -*- coding: utf-8 -*-

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestKnowledgeGraphEntity(unittest.TestCase):

    def test_entity_init(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("knowledge_graph", os.path.join(BASE_DIR, "modules", "knowledge_graph.py"))
        knowledge_graph = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(knowledge_graph)

        entity = knowledge_graph.KnowledgeGraphEntity('binary1', 'Binary', 'test.bin', {'path': '/tmp/test.bin', 'arch': 'amd64'})

        self.assertEqual(entity.entity_id, 'binary1')
        self.assertEqual(entity.entity_type, 'Binary')
        self.assertEqual(entity.name, 'test.bin')
        self.assertEqual(entity.properties['path'], '/tmp/test.bin')
        self.assertEqual(entity.properties['arch'], 'amd64')

    def test_entity_to_dict(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("knowledge_graph", os.path.join(BASE_DIR, "modules", "knowledge_graph.py"))
        knowledge_graph = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(knowledge_graph)

        entity = knowledge_graph.KnowledgeGraphEntity('cve-2021-34527', 'CVE', 'CVE-2021-34527', {'severity': 'Critical', 'description': 'Test CVE'})

        result = entity.to_dict()

        self.assertEqual(result['entity_id'], 'cve-2021-34527')
        self.assertEqual(result['entity_type'], 'CVE')
        self.assertEqual(result['properties']['severity'], 'Critical')


class TestKnowledgeGraphRelation(unittest.TestCase):

    def test_relation_init(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("knowledge_graph", os.path.join(BASE_DIR, "modules", "knowledge_graph.py"))
        knowledge_graph = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(knowledge_graph)

        relation = knowledge_graph.KnowledgeGraphRelation('binary1', 'cve-2021-1234', 'CONTAINS_VULN')

        self.assertEqual(relation.source_id, 'binary1')
        self.assertEqual(relation.target_id, 'cve-2021-1234')
        self.assertEqual(relation.relation_type, 'CONTAINS_VULN')
        self.assertEqual(relation.properties, {})


class TestVulnKnowledgeGraph(unittest.TestCase):

    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_init_with_storage_path(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("knowledge_graph", os.path.join(BASE_DIR, "modules", "knowledge_graph.py"))
        knowledge_graph = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(knowledge_graph)

        graph = knowledge_graph.VulnKnowledgeGraph(storage_path=self.m_tmp)

        self.assertEqual(graph.storage_path, self.m_tmp)
        self.assertTrue(os.path.exists(self.m_tmp))

    def test_add_entity(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("knowledge_graph", os.path.join(BASE_DIR, "modules", "knowledge_graph.py"))
        knowledge_graph = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(knowledge_graph)

        graph = knowledge_graph.VulnKnowledgeGraph(storage_path=self.m_tmp)

        entity_id = graph.add_entity('Binary', 'test.bin', {'path': '/tmp/test.bin'})

        self.assertIn(entity_id, graph.entities)
        self.assertEqual(graph.entities[entity_id].entity_type, 'Binary')
        self.assertEqual(graph.entities[entity_id].name, 'test.bin')

    def test_add_relation(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("knowledge_graph", os.path.join(BASE_DIR, "modules", "knowledge_graph.py"))
        knowledge_graph = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(knowledge_graph)

        graph = knowledge_graph.VulnKnowledgeGraph(storage_path=self.m_tmp)

        source_id = graph.add_entity('Binary', 'test.bin', {})
        target_id = graph.add_entity('Function', 'main', {})

        graph.add_relation(source_id, target_id, 'HAS_FUNCTION')

        self.assertEqual(len(graph.relations), 1)
        self.assertEqual(graph.relations[0].relation_type, 'HAS_FUNCTION')

    def test_export_json(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("knowledge_graph", os.path.join(BASE_DIR, "modules", "knowledge_graph.py"))
        knowledge_graph = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(knowledge_graph)

        graph = knowledge_graph.VulnKnowledgeGraph(storage_path=self.m_tmp)

        graph.add_entity('Binary', 'test.bin', {'name': 'test.bin'})

        export_path = os.path.join(self.m_tmp, 'export.json')
        result_path = graph.export_graph('json', export_path)

        self.assertTrue(os.path.exists(result_path))

        import json
        with open(result_path, 'r') as f:
            data = json.load(f)

        self.assertIn('entities', data)
        self.assertIn('relations', data)
        self.assertEqual(len(data['entities']), 1)


if __name__ == '__main__':
    unittest.main()
