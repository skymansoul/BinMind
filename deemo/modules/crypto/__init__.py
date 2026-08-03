"""
BinMind 密码学分析模块
-------------------------------
二进制制品的静态与动态密码学检测。
覆盖: 算法检测、误用扫描、流量分析、硬件哈希、PQC检测、
       隐写分析、签名校验、证书解析、熵评估、JWT审计、
       密码学不变式验证(S-box数学性质)、OTF S-box检测(嵌入式动态计算)、
       密钥扩展重构(轮常量校验)、跨二进制谱系追踪、
       子寄存器污点追踪(字节粒度常量时间)、实现偏移校准(指令混合比)、
       CFG熵指纹(无魔数密码检测)。

v0.8.0 — +subreg_taint, +drift_calibrator, +cfg_entropy_fingerprint
"""

__version__ = "0.8.0"
name = "crypto"

from . import src


def __getattr__(name):
    if hasattr(src, '__getattr__'):
        return src.__getattr__(name)
    raise AttributeError("module 'crypto' has no attribute '{}'".format(name))


__all__ = ["__version__", "name"]
