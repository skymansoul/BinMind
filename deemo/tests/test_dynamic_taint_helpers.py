"""
动态污点测试 — mock 工厂与共享 fixture.

提供:
  - create_mock_frida: 构造 Frida mock 模块链
  - create_mock_qbdi: 构造 QBDI mock 模块
  - mock_frida_context: Frida mock 上下文管理器
  - mock_qbdi_context: QBDI mock 上下文管理器
"""

from unittest.mock import MagicMock, patch


def create_mock_frida():
    """构造 Frida mock 模块链, 返回 (frida, device, session, script)."""
    mock_frida = MagicMock()
    mock_device = MagicMock()
    mock_session = MagicMock()
    mock_script = MagicMock()

    mock_frida.get_local_device.return_value = mock_device
    mock_device.spawn.return_value = 1234
    mock_device.attach.return_value = mock_session
    mock_session.create_script.return_value = mock_script

    return mock_frida, mock_device, mock_session, mock_script


def create_mock_qbdi():
    """构造 QBDI mock 模块."""
    return MagicMock()


def mock_frida_context():
    """返回 Frida mock 的 patch 链 (os.path.exists + isfile + sys.modules)."""
    from unittest.mock import patch as _p
    mock_frida, *_ = create_mock_frida()
    return [
        _p('os.path.exists', return_value=True),
        _p('os.path.isfile', return_value=True),
        _p.dict('sys.modules', {'frida': mock_frida}),
    ]


def mock_qbdi_context():
    """返回 QBDI mock 的 patch 链."""
    from unittest.mock import patch as _p
    mock_qbdi = create_mock_qbdi()
    return [
        _p('os.path.exists', return_value=True),
        _p('os.path.isfile', return_value=True),
        _p.dict('sys.modules', {'pyqbdi': mock_qbdi}),
    ]
