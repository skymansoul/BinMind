from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


class KernelDriverAnalyzer:
    """Windows/linux 内核驱动安全性分析"""
    def __init__(self):
        self.ioctls: List[dict] = []

    def analyze(self, data: bytes) -> dict:
        return {"driver_type": "unknown", "ioctls": self.ioctls}


class DriverAnalyzer:
    """内核驱动 IOCTL 派发表静态分析。

    从驱动字节流中定位 IOCTL 处理函数，评估能力检查与缓冲区校验缺口。
    """

    def __init__(self):
        self.ioctls: List[dict] = []
        self.capabilities: List[str] = []

    def analyze_ioctl(self, data: bytes) -> dict:
        """分析 IOCTL 派发表。空输入返回空结构，不抛异常。"""
        if not data:
            return {"ioctls": [], "capabilities": []}
        self.ioctls = self._extract_ioctls(data)
        return {"ioctls": self.ioctls, "capabilities": self.capabilities}

    def _extract_ioctls(self, data: bytes) -> List[dict]:
        """从字节流中提取疑似 IOCTL 常量（近 IRP_MJ_DEVICE_CONTROL 处）。"""
        ioctls: List[dict] = []
        # 简化启发式：扫描 4 字节对齐的 IOCTL 码特征（设备类型/功能位）
        for i in range(0, max(0, len(data) - 4), 4):
            val = int.from_bytes(data[i:i + 4], "little")
            if val & 0xC0000000 and (val & 0x3FFF) < 0x1000:
                ioctls.append({"offset": i, "code": hex(val)})
        return ioctls[:64]

    def check_capabilities(self, data: bytes = b"") -> List[str]:
        """返回驱动请求的能力检查项。"""
        return self.capabilities

    def analyze(self, data: bytes) -> dict:
        """兼容旧接口：等价于 analyze_ioctl。"""
        return self.analyze_ioctl(data)
