#
# 秘密数据追踪 —— 在函数内识别秘密输入源并追踪其数据流
#
# 秘密源识别策略（按置信度降序）：
#   1. 函数参数位于已知密码 API 的"密钥"位置 → 高置信度
#      (例: AES_set_encrypt_key(userKey, bits, expandedKey) 的 arg1)
#   2. 全局变量名称匹配密钥/密码相关模式 → 中置信度
#   3. 从调用上下文推断（函数被 crypto 模块调用且参数名含 key/secret/pass）→ 低置信度
#
# 传播规则（保守）：
# mov dst, src: dst 继承 src 的污点
#   - arith dst, src1, src2: dst 继承 src1 和 src2 的污点
#   - xor dst, src: 双秘密输入的异或不被视为去污点（OTP 模式不适用于密钥混合）
# 立即数赋值: 污点被清除（立即数不是秘密）
# 内存写入: mem[addr] 继承被写数据的污点
#   - 内存读取: dst 继承 mem[addr] 的污点（如果 mem 被标记为秘密存储区）
#
# 关键假设：常量时间代码中，密钥相关的条件分支和数组索引在源码层就已被
# 消除（由开发者手动保证）。本模块检测的是二进制层面的残留违规——
# 编译器优化（如 cmov 替代 jcc）可能在二进制层消除了源码的违规
# 但也可能引入新的（如将比较展开为分支）。本分析对被编译器消除的违规
# 不做误报——只报告二进制中实际残留的模式

import logging
from typing import Dict, List, Set, Tuple, Optional  # noqa: F401
from dataclasses import dataclass, field
from enum import Enum, auto

logger = logging.getLogger(__name__)


class SecretClass(Enum):
    KEY_PARAM = auto()       # 函数参数——高置信度秘密源
    GLOBAL_SECRET = auto()   # 全局变量匹配密码模式
    DERIVED_KEY = auto()     # 轮密钥/子密钥等中间产物
    INFERRED_SECRET = auto() # 从调用上下文推断——低置信度


@dataclass
class SecretSource:
    """一个秘密数据源"""
    source_id: str           # 标识符——寄存器名或全局变量名
    source_class: SecretClass
    func_name: str
    address: int
    confidence: float        # [0, 1]


@dataclass
class SecretTaint:
    """一个被污点的实体——寄存器或内存位置"""
    entity: str              # 'rax', 'rsp+0x8', '[rbp-0x20]'
    sources: Set[str]        # 来源 SecretSource.source_id 的集合
    depth: int               # 从源出发的传播步数


# 已知密码 API 的参数位置映射

# (函数名模式, 秘密参数的索引位, 描述)
_CRYPTO_API_SECRET_PARAMS = [
    # OpenSSL / BoringSSL
    ('AES_set_encrypt_key', 0, 'userKey'),
    ('AES_set_decrypt_key', 0, 'userKey'),
    ('AES_encrypt', 1, 'key_schedule'),
    ('AES_decrypt', 1, 'key_schedule'),
    ('HMAC_Init_ex', 2, 'key'),
    ('EVP_CipherInit_ex', 3, 'key'),
    ('EVP_EncryptInit_ex', 3, 'key'),
    ('EVP_DecryptInit_ex', 3, 'key'),
    ('SHA256_Init', -1, 'none'),  # SHA 无密钥——但标记为检查对象
    # libsodium
    ('crypto_secretbox', 1, 'key'),
    ('crypto_secretbox_open', 1, 'key'),
    ('crypto_auth', 1, 'key'),
    ('crypto_sign', 1, 'secret_key'),
    ('crypto_stream_xor', 0, 'key'),
    # Windows CNG (近似——参数位置取决于具体 API)
    ('BCryptEncrypt', 6, 'key_object'),
    ('BCryptDecrypt', 6, 'key_object'),
    ('BCryptGenerateSymmetricKey', 2, 'secret'),
    # NaCl
    ('crypto_box', 2, 'secret'),
    ('crypto_box_open', 2, 'secret'),
]

# 全局变量名匹配模式
_GLOBAL_SECRET_PATTERNS = [
    'key', 'secret', 'password', 'passwd', 'nonce', 'iv',
    'private', 'sk', 'master_key', 'ekey', 'dkey',
    'sbox', 'T0', 'Te0', 'Td0',  # AES 表——虽非密钥但访问模式可泄露密钥
]


def identify_secret_sources(
    func_name: str,
    func_addr: int,
    params: List[str],
    imports: List[str],
    global_vars: Dict[str, int],
) -> List[SecretSource]:
    """识别函数中的秘密数据源
    
    参数:
    func_name: 函数名
    func_addr: 函数地址
    params: 参数名列表（从反编译器推断）
    imports: 调用者使用的导入符号列表
    global_vars: {name: addr} 全局变量映射
    """
    sources = []
    already_identified: Set[str] = set()  # 防重复——已高置信度识别的源不被低置信度策略覆盖

    # 策略 1: 密码 API 参数检查
    for api_pattern, param_idx, param_desc in _CRYPTO_API_SECRET_PARAMS:
        if api_pattern.lower() in func_name.lower():
            if 0 <= param_idx < len(params):
                sid = params[param_idx]
                sources.append(SecretSource(
                    source_id=sid,
                    source_class=SecretClass.KEY_PARAM,
                    func_name=func_name, address=func_addr,
                    confidence=0.95,
                ))
                already_identified.add(sid)
            break  # 只匹配最佳 API 模式

    # 策略 2: 参数名匹配——跳过已被策略 1 识别的高置信度源
    for param in params:
        if param in already_identified:
            continue
        param_lower = param.lower()
        for pat in _GLOBAL_SECRET_PATTERNS:
            if pat in param_lower:
                sources.append(SecretSource(
                    source_id=param,
                    source_class=SecretClass.INFERRED_SECRET,
                    func_name=func_name, address=func_addr,
                    confidence=0.6,
                ))
                already_identified.add(param)
                break

    # 策略 3: 全局变量名匹配
    for gvar_name in global_vars:
        gv_lower = gvar_name.lower()
        for pat in _GLOBAL_SECRET_PATTERNS:
            if pat in gv_lower:
                sources.append(SecretSource(
                    source_id=gvar_name,
                    source_class=SecretClass.GLOBAL_SECRET,
                    func_name=func_name, address=func_addr,
                    confidence=0.7,
                ))
                break

    return sources


def propagate_taint_intraprocedural(
    sources: List[SecretSource],
    insns: List[Tuple[str, List[str]]],
) -> Dict[str, SecretTaint]:
    """过程内污点传播——从秘密源出发，正向传播污点标记
    
    返回 {enti: SecretTaint} 映射所有被污染的实体
    
    算法：迭代定点——重复扫描指令直到不再有新污点产生
    效率对 <1000 条指令的函数可接受（每轮 O(×E)，=指令数, E=实体数）
    """
    taints: Dict[str, SecretTaint] = {}

    # 初始化污点源
    for src in sources:
        taints[src.source_id] = SecretTaint(
            entity=src.source_id,
            sources={src.source_id},
            depth=0,
        )

    MAX_ITER = 50  # 防止极端情况下的无限循环
    for iteration in range(MAX_ITER):
        changed = False

        for mn, ops in insns:
            if mn in ('mov', 'movsx', 'movzx', 'lea'):
                if len(ops) >= 2 and ops[1] in taints:
                    t = taints[ops[1]]
                    if ops[0] not in taints or taints[ops[0]].depth > t.depth + 1:
                        taints[ops[0]] = SecretTaint(
                            entity=ops[0], sources=t.sources, depth=t.depth + 1)
                        changed = True

            elif mn in ('add', 'sub', 'and', 'or', 'xor', 'shl', 'shr',
                       'sar', 'rol', 'ror', 'mul', 'imul'):
                srcs = [o for o in ops[1:] if o in taints]
                if srcs and ops[0] not in taints:
                    combined = set()
                    min_depth = 999
                    for s in srcs:
                        combined |= taints[s].sources
                        min_depth = min(min_depth, taints[s].depth)
                    taints[ops[0]] = SecretTaint(
                        entity=ops[0], sources=combined, depth=min_depth + 1)
                    changed = True

        if not changed:
            break

    return taints
