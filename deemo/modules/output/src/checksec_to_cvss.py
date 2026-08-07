"""
checksec → CVSS 环境度量推断规则。

将二进制加固检测结果 (NX/PIE/Canary/RELRO/FORTIFY)
映射为 CVSS 3.1 的 Modified Base Metrics 和 Security Requirements。

这是本项目独有的创新: 现有 CVSS 工具均需人工输入环境度量，
本项目利用 checksec 加固状态自动推断。

映射规则:
  加固缺失 → Modified 度量恶化 (攻击条件更有利)
    NX 禁用      → MI/MA = High (栈/堆可执行)
    PIE 禁用      → MAC = Low (固定地址), MPR = Low
    Canary 禁用   → MC/MI = High (栈溢出可控返回地址)
    RELRO 不完整  → MI = High (GOT 可覆写)
    FORTIFY 缺失  → MC/MI/MA = High (内存破坏更易触发)

  加固缺失 → 安全需求提升 (脆弱资产需要更多保护)
    极弱加固 (≤1/5) → CR/IR/AR 各升一档

导入表敏感函数模式匹配:
  加密/SSL  → CR=H (处理敏感数据)
  exec/system → IR=H (影响系统完整性)
  socket/bind → AR=H (网络服务在关键路径)

修改记录:
2025-07-24 15:22 - 独立维护推断规则
"""

import logging
from typing import Any, Dict

_log = logging.getLogger(__name__)


def infer_modified_metrics(
    checksec: Dict[str, Any],
    base_metrics: Dict[str, str]
) -> Dict[str, str]:
    """
    从 checksec 结果推断 Modified Base Metrics。

    Modified = base_metrics 的副本，根据加固状态逐项调整。
    加固存在 → 维持 base_metrics 值 (默认假设攻击者面对的是加固目标)。
    加固缺失 → 攻击条件恶化 → Modified 度量向不利方向调整。

    注意: 不修改 MAV/MS/MUI — 这三项由二进制架构和漏洞类型决定，
    与加固状态无直接因果，由外部传入 base_metrics 覆盖。
    """
    modified = dict(base_metrics)

    nx_enabled = checksec.get('NX', True)
    pie_enabled = checksec.get('PIE', True)
    canary_enabled = checksec.get('Canary', True)
    relro = checksec.get('RELRO', '').lower()
    fortify = checksec.get('FORTIFY', False) or checksec.get('FORTIFY_SOURCE', False)

    if not nx_enabled:
        modified['MI'] = 'H'
        modified['MA'] = 'H'

    if not pie_enabled:
        modified['MAC'] = 'L'
        # 固定基址也使特权提升更容易 — 地址可预测 → ROP/JOP gadget 选择更丰富
        if modified.get('MPR', 'N') == 'N':
            modified['MPR'] = 'L'

    if not canary_enabled:
        if modified.get('MC', 'N') != 'H':
            modified['MC'] = 'H'
        if modified.get('MI', 'N') != 'H':
            modified['MI'] = 'H'

    if 'full' not in relro:
        modified['MI'] = 'H'
        if 'no' in relro or 'none' in relro:
            modified['MA'] = max(
                modified.get('MA', 'N'), 'H',
                key=lambda x: {'N': 0, 'L': 1, 'H': 2}.get(x, 0)
            )

    if not fortify:
        for key in ('MC', 'MI', 'MA'):
            modified[key] = 'H'

    return modified


def infer_security_requirements(
    checksec: Dict[str, Any],
    imports: list = None,
    binary_type: str = ''
) -> Dict[str, str]:
    """
    从 checksec 和导入表推断 Security Requirements (CR/IR/AR)。

    CR: 二进制是否处理敏感数据 → 导入加密/文件读取函数
    IR: 二进制输出是否影响系统完整性 → 导入 exec/文件写入函数
    AR: 二进制是否在关键路径 → 导入网络/守护进程函数

    加固评分作为辅助信号: 极弱加固体 → 所有需求提档 (因为风险暴露面更大)。
    """
    req = {'CR': 'M', 'IR': 'M', 'AR': 'M'}

    if imports:
        import_names = []
        for imp in imports:
            if isinstance(imp, dict):
                import_names.append(imp.get('name', '').lower())
            elif isinstance(imp, str):
                import_names.append(imp.lower())

        joined = ' '.join(import_names)

        # CR: 敏感数据处理
        crypto_set = {'aes', 'rsa', 'ssl', 'tls', 'crypt', 'encrypt', 'decrypt',
                      'hash', 'sha', 'md5', 'hmac', 'random', 'key'}
        file_read_set = {'fopen', 'open', 'read', 'fread', 'fgets', 'mmap',
                         'stat', 'access', 'opendir', 'readdir'}
        if any(p in joined for p in crypto_set):
            req['CR'] = 'H'
        elif any(p in joined for p in file_read_set):
            req['CR'] = 'M'

        # IR: 系统修改
        exec_set = {'exec', 'system', 'popen', 'fork', 'createprocess',
                    'winexec', 'shell', 'cmd', 'spawn'}
        file_write_set = {'fwrite', 'write', 'fputs', 'fprintf', 'rename',
                          'unlink', 'chmod', 'mkdir', 'creat'}
        if any(p in joined for p in exec_set):
            req['IR'] = 'H'
        elif any(p in joined for p in file_write_set):
            req['IR'] = 'M'

        # AR: 关键路径
        net_set = {'socket', 'bind', 'listen', 'accept', 'connect',
                   'send', 'recv', 'sendto', 'recvfrom', 'gethostbyname',
                   'getaddrinfo', 'setsockopt'}
        daemon_set = {'daemon', 'fork', 'setsid', 'sigaction', 'signal',
                      'setuid', 'setgid', 'chroot'}
        if any(p in joined for p in net_set):
            req['AR'] = 'H'
        elif any(p in joined for p in daemon_set):
            req['AR'] = 'M'

    # 加固评分: 极弱 → 需求提升
    hardening_score = sum([
        checksec.get('NX', False),
        checksec.get('PIE', False),
        checksec.get('Canary', False),
        'full' in checksec.get('RELRO', '').lower(),
        checksec.get('FORTIFY', False),
    ])
    if hardening_score <= 1:
        for key in req:
            if req[key] == 'M':
                req[key] = 'H'
            elif req[key] == 'L':
                req[key] = 'M'

    return req
