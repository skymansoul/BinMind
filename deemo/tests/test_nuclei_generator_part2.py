

# -*- coding: utf-8 -*-

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.nuclei_generator import (
    HttpRequest,
    MatchCondition,
)


class TestHttpRequest(unittest.TestCase):
    """HttpRequest 数据类测试"""

    def test_raw_request(self):
        """测试原始请求"""
        request = HttpRequest(
            method='GET',
            path='/',
            raw='GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        )

        self.assertIsNotNone(request.raw)


class TestMatchCondition(unittest.TestCase):
    """MatchCondition 数据类测试"""

    def test_negative_condition(self):
        """测试否定条件"""
        condition = MatchCondition(
            match_type='word',
            condition='success',
            part='body',
            negative=True
        )

        result = condition.to_dict()

        self.assertIn('negative', result)
        self.assertTrue(result['negative'])



if __name__ == '__main__':
    unittest.main()


