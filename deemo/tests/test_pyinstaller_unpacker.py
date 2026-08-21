
"""
PyInstaller/Nuitka 解包模块测试
"""
import os
import sys
import unittest
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.pyinstaller_unpacker import (
    PyInstallerUnpacker, PycFile, UnpackResult, PYTHON_MAGIC_NUMBERS,
    PackerType, PythonVersion
)


class TestPyInstallerUnpacker(unittest.TestCase):
    """PyInstaller/Nuitka 解包器测试类"""

    def setUp(self):
        """测试前准备"""
        self.m_tmp = tempfile.mkdtemp()
        self.unpacker = PyInstallerUnpacker(output_dir=self.m_tmp)

    def tearDown(self):
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)

    def test_python_magic_numbers(self):
        """测试 Python 魔数映射表"""
        # 检查常见 Python 版本的魔数存在
        self.assertIn((3, 8), PYTHON_MAGIC_NUMBERS)
        self.assertIn((3, 9), PYTHON_MAGIC_NUMBERS)
        self.assertIn((3, 10), PYTHON_MAGIC_NUMBERS)
        self.assertIn((3, 11), PYTHON_MAGIC_NUMBERS)

        # 检查魔数格式
        magic_38 = PYTHON_MAGIC_NUMBERS[(3, 8)]
        self.assertEqual(len(magic_38), 4)

    def test_detect_packer_type_none(self):
        # 创建一个普通文件
        test_file = os.path.join(self.m_tmp, 'test.txt')
        with open(test_file, 'wb') as f:
            f.write(b'Hello World')

        result = self.unpacker.detect_packer(test_file)
        self.assertEqual(result, PackerType.NONE)

    def test_detect_packer_pyinstaller(self):
        """测试检测 PyInstaller 打包文件"""
        # 创建模拟 PyInstaller 文件（包含签名）
        test_file = os.path.join(self.m_tmp, 'test_pyinstaller.exe')
        with open(test_file, 'wb') as f:
            # PyInstaller 签名
            f.write(b'MEI\x0c\x0b\x0a\x0b\x0e')
            f.write(b'\x00' * 100)

        result = self.unpacker.detect_packer(test_file)
        self.assertEqual(result, PackerType.PYINSTALLER)

    def test_detect_packer_nuitka(self):
        # 创建模拟 Nuitka 文件
        test_file = os.path.join(self.m_tmp, 'test_nuitka.exe')
        with open(test_file, 'wb') as f:
            # Nuitka 签名
            f.write(b'Nuitka')
            f.write(b'\x00' * 100)

        result = self.unpacker.detect_packer(test_file)
        self.assertEqual(result, PackerType.NUITKA)

    def test_pyc_file_dataclass(self):
        """测试 PycFile 数据类"""
        pyc = PycFile(
            filename='test.pyc',
            python_version=(3, 10),
            magic_number=b'\xa7\r\r\n',
            content=b'\x00' * 100,
            source_code=None
        )

        self.assertEqual(pyc.filename, 'test.pyc')
        self.assertEqual(pyc.python_version, (3, 10))
        self.assertIsNotNone(pyc.magic_number)
        self.assertEqual(len(pyc.content), 100)

    def test_unpack_result_dataclass(self):
        """测试 UnpackResult 数据类"""
        result = UnpackResult(
            packer_type=PackerType.PYINSTALLER,
            pyc_files=[],
            source_files=[],
            metadata={'version': '3.10'},
            errors=[]
        )

        self.assertEqual(result.packer_type, PackerType.PYINSTALLER)
        self.assertIsInstance(result.pyc_files, list)
        self.assertIn('version', result.metadata)

    def test_find_embedded_pyc(self):
        """测试搜索嵌入的 pyc 文件"""
        # 创建包含 pyc 魔数的数据
        magic_310 = PYTHON_MAGIC_NUMBERS.get((3, 10), b'\xa7\r\r\n')
        test_data = b'\x00' * 50 + magic_310 + b'\x00' * 100

        pyc_files = self.unpacker._find_embedded_pyc(test_data)

        # 应该至少找到一个
        self.assertGreaterEqual(len(pyc_files), 1)

    def test_unpack_nonexistent_file(self):
        """测试解包不存在的文件"""
        result = self.unpacker.unpack('/nonexistent/file.exe')

        self.assertEqual(result.packer_type, PackerType.NONE)
        self.assertGreater(len(result.errors), 0)

    def test_generate_report(self):
        """测试生成报告"""
        pyc_file = PycFile(
            filename='test.pyc',
            python_version=(3, 10),
            magic_number=b'\xa7\r\r\n',
            content=b'\x00' * 100,
            source_code='def test(): pass'
        )

        result = UnpackResult(
            packer_type=PackerType.PYINSTALLER,
            pyc_files=[pyc_file],
            source_files=['test.py'],
            metadata={'version': '3.10'},
            errors=[]
        )

        report = self.unpacker.generate_report(result)

        self.assertIn('PyInstaller', report)
        self.assertIn('test.pyc', report)
        self.assertIn('test.py', report)

    def test_save_result(self):
        """测试保存结果"""
        result = UnpackResult(
            packer_type=PackerType.PYINSTALLER,
            pyc_files=[],
            source_files=[],
            metadata={'test': 'value'},
            errors=[]
        )

        saved_path = self.unpacker.save_result(result, 'test_result')

        self.assertTrue(os.path.exists(saved_path))
        self.assertTrue(saved_path.endswith('.json'))

    def test_packer_type_enum(self):
        """测试 PackerType 枚举"""
        self.assertEqual(PackerType.NONE.value, 'none')
        self.assertEqual(PackerType.PYINSTALLER.value, 'pyinstaller')
        self.assertEqual(PackerType.NUITKA.value, 'nuitka')
        self.assertEqual(PackerType.UNKNOWN.value, 'unknown')

    def test_python_version_enum(self):
        """测试 PythonVersion 枚举"""
        self.assertEqual(PythonVersion.PY38.value, (3, 8))
        self.assertEqual(PythonVersion.PY39.value, (3, 9))
        self.assertEqual(PythonVersion.PY310.value, (3, 10))
        self.assertEqual(PythonVersion.PY311.value, (3, 11))
        self.assertEqual(PythonVersion.UNKNOWN.value, (0, 0))


class TestPycFile(unittest.TestCase):
    """PycFile 数据类测试"""

    def test_to_dict(self):
        """测试转换为字典"""
        pyc = PycFile(
            filename='module.pyc',
            python_version=(3, 10),
            magic_number=b'\xa7\r\r\n',
            content=b'test content',
            source_code='print("hello")'
        )

        result = pyc.to_dict()

        self.assertIn('filename', result)
        self.assertIn('python_version', result)
        self.assertIn('source_code', result)
        self.assertEqual(result['filename'], 'module.pyc')


class TestUnpackResult(unittest.TestCase):
    """UnpackResult 数据类测试"""

    def test_to_dict(self):
        """测试转换为字典"""
        result = UnpackResult(
            packer_type=PackerType.PYINSTALLER,
            pyc_files=[],
            source_files=['main.py', 'utils.py'],
            metadata={'entry': 'main'},
            errors=['test error']
        )

        data = result.to_dict()

        self.assertIn('packer_type', data)
        self.assertIn('source_files', data)
        self.assertIn('metadata', data)
        self.assertIn('errors', data)
        self.assertEqual(data['packer_type'], 'pyinstaller')



if __name__ == '__main__':
    unittest.main()


