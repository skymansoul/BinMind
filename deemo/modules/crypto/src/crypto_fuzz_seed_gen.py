"""
密码学模糊测试种子生成 — 从检测到的密码协议状态机生成协议感知的fuzzing种子和语法。

修改记录:
  2025-09-13 10:22 — 初始实现: 协议语法推断/状态转移种子/边界值/变异策略

设计意图:
  协议fuzzing(AFLNet/Boofuzz/Scapy)需要种子输入和协议语法作为起点。
  手工编写种子和语法耗时且需要协议专业知识。本模块从静态分析推断的
  协议状态机和密码学检测结果中自动生成fuzzing种子和变异策略。

  生成三类种子:
    S1 (握手种子): 每个协议状态的合法输入 → 测试状态转移的正确性。
    S2 (边界种子): 密钥长度/证书大小/nonce值的边界条件 → 测试缓冲区处理。
    S3 (异常种子): IV复用/弱密码套件/降级请求 → 测试安全策略执行。

  输出格式: JSON种子文件 + 变异策略描述 → 可直接导入fuzzing框架。

参考:
  - AFLNet (ICST 2020): 有状态网络协议的灰盒Fuzzer — 使用协议状态机指导变异。
  - Boofuzz (2024): Python协议fuzzing框架 — 基于语法描述的Fuzzing。
  - ProtocolGPT (arXiv:2405.00393): LLM推断协议状态机用于Fuzzing。
  - CLFuzz (TOSEM 2025): 密码学库的差异Fuzzing。

边界条件:
  - 生成的种子基于静态推断 — 运行时状态转移可能与静态分析不同。
  - 种子的有效性取决于协议状态机的准确性。
  - 自定义/私有协议的种子生成精确度有限。
"""

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class SeedType(Enum):
    HANDSHAKE = 0
    BOUNDARY = 1
    ANOMALY = 2


@dataclass
class FuzzSeed:
    seed_id: str = ""
    seed_type: SeedType = SeedType.HANDSHAKE
    protocol_phase: str = ""       # INIT / HELLO / KEY_EXCHANGE / etc.
    description: str = ""
    # 种子内容(十六进制或结构化描述)
    seed_content_hex: str = ""
    expected_behavior: str = ""    # 合法行为 / 异常拒绝 / 静默接受(危险)
    mutation_strategy: str = ""
    priority: str = "MEDIUM"       # HIGH / MEDIUM / LOW


@dataclass
class FuzzSeedSuite:
    protocol_name: str = ""
    total_seeds: int = 0
    seeds: List[FuzzSeed] = field(default_factory=list)
    mutation_strategies: List[str] = field(default_factory=list)


# ── TLS 1.2/1.3 握手种子模板 ──

_TLS_HANDSHAKE_TEMPLATES: Dict[str, List[FuzzSeed]] = {
    'TLS': [
        FuzzSeed('TLS-HS-01', SeedType.HANDSHAKE, 'HELLO',
                 'ClientHello (合法密码套件)',
                 seed_content_hex=(
                     '16 03 01 00 00  '  # TLS record header
                     '01 00 00 00      '  # ClientHello type
                 ),
                 expected_behavior='ServerHello或HelloRetryRequest',
                 mutation_strategy='变异密码套件列表/扩展/压缩方法',
                 priority='HIGH'),
        FuzzSeed('TLS-HS-02', SeedType.HANDSHAKE, 'KEY_EXCHANGE',
                 'ClientKeyExchange (合法DH/ECDH公钥)',
                 seed_content_hex='16 03 03 00 00  10 00 00 00',
                 expected_behavior='ChangeCipherSpec + Finished',
                 mutation_strategy='变异公钥值/长度/点格式',
                 priority='HIGH'),
        FuzzSeed('TLS-BD-01', SeedType.BOUNDARY, 'HELLO',
                 'ClientHello (超长密码套件列表→1000个套件)',
                 seed_content_hex='16 03 01 07 D0  01 00 07 CC',
                 expected_behavior='拒绝或截断(不应崩溃或缓冲区溢出)',
                 mutation_strategy='逐步增加套件数量和扩展长度',
                 priority='HIGH'),
        FuzzSeed('TLS-BD-02', SeedType.BOUNDARY, 'KEY_EXCHANGE',
                 'ClientKeyExchange (0长度密钥)',
                 seed_content_hex='16 03 03 00 02  10 00 00 00',
                 expected_behavior='拒绝+关闭连接',
                 mutation_strategy='变异长度字段: 0/-1/MAX_UINT16',
                 priority='HIGH'),
        FuzzSeed('TLS-AN-01', SeedType.ANOMALY, 'HELLO',
                 'ClientHello (仅含已废弃密码套件: TLS_RSA_WITH_DES_CBC_SHA)',
                 seed_content_hex='16 03 01 00 00  01 00 00 02 00 09',
                 expected_behavior='拒绝(不应接受DES套件)',
                 mutation_strategy='仅发送弱/废弃套件',
                 priority='MEDIUM'),
        FuzzSeed('TLS-AN-02', SeedType.ANOMALY, 'HELLO',
                 'ClientHello (请求降级到SSLv3)',
                 seed_content_hex='16 03 00 00 00  01 00 00 00',
                 expected_behavior='拒绝(不应接受SSLv3降级)',
                 mutation_strategy='请求更低协议版本',
                 priority='MEDIUM'),
    ],
    'SSH': [
        FuzzSeed('SSH-HS-01', SeedType.HANDSHAKE, 'HELLO',
                 'SSH版本字符串交换 (SSH-2.0-...)',
                 seed_content_hex='53 53 48 2D 32 2E 30 2D 0D 0A',
                 expected_behavior='对端返回版本字符串',
                 mutation_strategy='变异版本号/注释字段/超长标识',
                 priority='HIGH'),
    ],
    'IPSec': [
        FuzzSeed('IKE-HS-01', SeedType.HANDSHAKE, 'HELLO',
                 'IKE_SA_INIT (提议+密钥交换)',
                 seed_content_hex='00 00 00 00 00 00 00 00  21 20 22 08',
                 expected_behavior='IKE_SA_INIT响应',
                 mutation_strategy='变异提议/变换/密钥交换载荷',
                 priority='HIGH'),
    ],
}


def generate_fuzz_seeds(protocol_findings: Optional[List] = None,
                        crypto_findings: Optional[List] = None
                        ) -> FuzzSeedSuite:
    """
    从协议状态机和密码学检测结果生成Fuzzing种子套件。
    """
    all_seeds: List[FuzzSeed] = []
    proto_name = 'Custom'

    if protocol_findings:
        for pf in protocol_findings:
            try:
                proto = getattr(pf, 'protocol_name', '')
                match = getattr(pf, 'best_match', '')
                if match:
                    proto_name = match
                elif proto and proto != 'Custom':
                    proto_name = proto

                # 从协议指纹匹配种子模板
                for known_proto, templates in _TLS_HANDSHAKE_TEMPLATES.items():
                    if known_proto in proto_name or known_proto in match:
                        all_seeds.extend(templates)
                        break
            except Exception:
                pass

    # 若未匹配到已知协议模板, 生成通用种子
    if not all_seeds and crypto_findings:
        algos = set()
        for f in crypto_findings:
            try:
                algos.add(getattr(f, 'algorithm', ''))
            except Exception:
                pass

        for algo in algos:
            all_seeds.append(FuzzSeed(
                seed_id=f'GEN-HS-{algo}',
                seed_type=SeedType.HANDSHAKE,
                protocol_phase='DATA',
                description=f'{algo}加密数据块 (合法明文→密文)',
                expected_behavior='正常密文输出',
                mutation_strategy=f'变异{algo}输入: 超长/空/非对齐/特殊字节序列',
                priority='MEDIUM'))
            all_seeds.append(FuzzSeed(
                seed_id=f'GEN-BD-{algo}',
                seed_type=SeedType.BOUNDARY,
                protocol_phase='DATA',
                description=f'{algo}边界测试: 0长度/1字节/MAX大小输入',
                expected_behavior='优雅处理边界情况',
                mutation_strategy='0/1/65535字节输入',
                priority='HIGH'))

    # 通用变异策略
    strategies = [
        'BYTE_FLIP: 翻转随机字节',
        'ARITHMETIC: 整数字段±1/±128/±32768',
        'LENGTH_FIELD: 变异长度字段为0/MAX/不一致值',
        'REORDER: 重排扩展/载荷顺序',
        'DUPLICATE: 复制载荷段',
        'TRUNCATE: 截断到协议边界以下',
    ]

    return FuzzSeedSuite(
        protocol_name=proto_name,
        total_seeds=len(all_seeds),
        seeds=all_seeds,
        mutation_strategies=strategies)


def export_seeds_json(suite: FuzzSeedSuite) -> str:
    """导出种子为JSON格式。"""
    seeds_json = []
    for s in suite.seeds:
        seeds_json.append({
            'id': s.seed_id,
            'type': s.seed_type.name,
            'phase': s.protocol_phase,
            'description': s.description,
            'seed_hex': s.seed_content_hex.replace(' ', '')[:64],
            'expected': s.expected_behavior,
            'mutation': s.mutation_strategy,
            'priority': s.priority,
        })
    return json.dumps({
        'protocol': suite.protocol_name,
        'total_seeds': suite.total_seeds,
        'seeds': seeds_json,
        'mutation_strategies': suite.mutation_strategies,
    }, indent=2, ensure_ascii=False)
