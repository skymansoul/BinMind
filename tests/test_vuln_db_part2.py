
import os
import sys
import tempfile
import json
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))



class TestVulnDbWithMocks(unittest.TestCase):

    def test_get_vuln_db_function(self):
        from modules.vuln.vuln_db import get_vuln_db, VulnerabilityDatabase

        db = get_vuln_db()
        self.assertIsInstance(db, VulnerabilityDatabase)
        db.close()

    def test_empty_db_operations(self):
        temp_db = tempfile.mktemp(suffix='.db')
        from modules.vuln.vuln_db import VulnerabilityDatabase
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
