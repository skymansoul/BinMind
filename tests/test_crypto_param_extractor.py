# 测CryptoParamExtractor的init和extract_parameters，参数格式有hex/字符串/base64好几种
# 反编译代码有时候变量名会丢，匹配是模糊的

import unittest
import os
import importlib.util
# from typing import Any  # 备着

_DEBUG_FLAG = False


class TestCryptoParamExtractor(unittest.TestCase):
    """CryptoParamExtractor的自测 -- 初始化 + 参数提取"""

    def test_extractor_initialization(self):
        """初始化成功，传一个不存在的binary path也没事，extract_parameters才报错"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'crypto_param_extractor.py')
        spec = importlib.util.spec_from_file_location('crypto_param_extractor', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        extractor = module.CryptoParamExtractor('/path/to/binary')
        self.assertIsNotNone(extractor)

    def test_extract_parameters(self):
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'crypto_param_extractor.py')
        spec = importlib.util.spec_from_file_location('crypto_param_extractor', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        extractor = module.CryptoParamExtractor('/path/to/binary')
        result = extractor.extract_parameters('AES_encrypt(key, data);')

        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()
