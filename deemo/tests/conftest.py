"""
pytest 配置文件 - 定义测试夹具和共享资源
"""

import os
import sys
import pytest
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(scope="session")
def project_root():
    """项目根目录"""
    return Path(__file__).parent.parent


@pytest.fixture(scope="session")
def test_data_dir(project_root):
    """测试数据目录"""
    return project_root / "tests" / "data"


@pytest.fixture(scope="session")
def temp_dir():
    """临时目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture(scope="function")
def temp_file():
    """临时文件"""
    fd, path = tempfile.mkstemp()
    try:
        yield Path(path)
    finally:
        os.close(fd)
        os.unlink(path)


@pytest.fixture(scope="session")
def sample_binary(test_data_dir):
    """示例二进制文件路径（如果存在）"""
    sample = test_data_dir / "sample.bin"
    if sample.exists():
        return sample
    return None


@pytest.fixture(scope="function")
def mock_config():
    """模拟配置"""
    return {
        "logging": {"level": "DEBUG", "format": "json"},
        "analysis": {"timeout": 60, "max_iterations": 10},
        "resource": {"memory_limit_mb": 1024, "cpu_cores": 2}
    }


@pytest.fixture(scope="function")
def mock_binary_path(temp_file):
    """创建一个模拟的二进制文件"""
    with open(temp_file, 'wb') as f:
        f.write(b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00')
    return temp_file


@pytest.fixture(scope="session")
def juliet_testcases_dir(project_root):
    """Juliet测试用例目录"""
    return project_root / "testcases" / "juliet"


def pytest_addoption(parser):
    """添加自定义命令行选项"""
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests"
    )
    parser.addoption(
        "--run-security",
        action="store_true",
        default=False,
        help="Run security tests"
    )


def pytest_collection_modifyitems(config, items):
    """根据命令行选项过滤测试"""
    if not config.getoption("--run-slow"):
        skip_slow = pytest.mark.skip(reason="Need --run-slow option to run")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)
    
    if not config.getoption("--run-security"):
        skip_security = pytest.mark.skip(reason="Need --run-security option to run")
        for item in items:
            if "security" in item.keywords:
                item.add_marker(skip_security)