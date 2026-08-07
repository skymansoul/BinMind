"""网络拓扑映射 —— LLDP/CDP帧解析、被动OS指纹识别、网络层次推断。

通过解析链路层发现协议（LLDP/CDP）和被动TCP/IP栈指纹识别，构建网络拓扑图和设备角色图谱。

- IEEE 802.1AB (LLDP)
- p0f v3
- ET-OSF
"""
# 拆分后各子模块统一从此入口导出，保持外部导入路径不变
from .topology_types import (
    LldpNeighbor, OsFingerprint, NetworkDevice,
)
from .topology_lldp import LldpParser
from .topology_os_fp import PassiveOsFingerprinter
from .topology_engine import TopologyMapper

__all__ = ["TopologyMapper", "LldpParser", "PassiveOsFingerprinter",
           "LldpNeighbor", "OsFingerprint", "NetworkDevice"]
