"""
启发式置信度评分 — LLM 未配置时的降级路径。

设计意图:
  纯模式匹配对每次命中给出固定严重度, 无法区分真误用与数据巧合(测试向量/
  查表/文档字符串/随机字节). 本评分器以 5 类证据调整置信度:
    (1) 严重度基准          — 类别本身的风险权重;
    (2) API 邻近度          — 上下游是否存在密钥生成/加密调用上下文;
    (3) 邻域熵              — 数据节常量 vs 随机/压缩数据的判别;
    (4) 重复度惩罚          — 同值多次出现 → 查表/测试向量嫌疑;
    (5) 跨单元传播加成      — 同常量在其它编译单元出现 → 强误用信号。

边界条件:
  - 输出被钳制在 [0.05, 0.98], 避免 0/1 极端值导致的过滤震荡。
  - 聚合命中 (ECB_ARTIFACT / GCM_NONCE_REUSE 等无单点锚定) 一律压低 API 权重。
  - 所有证据均为可选参数, 便于上层流水线逐步补齐后增量调整。
"""

from typing import Dict, Optional

# 严重度 → 基准置信度 (与 crypto_misuse.SEVERITY 的等级一致)
SEVERITY_BASE: Dict[str, float] = {
    'CRITICAL': 0.92,
    'HIGH': 0.80,
    'MEDIUM': 0.65,
    'LOW': 0.50,
    'INFO': 0.30,
}

# 常量: 各证据的加权系数 — 依据消融经验设定, 不轻易改动
_API_WEIGHT_NO_CONTEXT = 0.45   # 完全无加密上下文 → 假阳性概率高
_API_WEIGHT_MAX = 1.05          # 上下游均有加密上下文 → 强支持
_ENTROPY_RANDOM_THRESHOLD = 0.95  # 邻域熵超过此值 → 随机/压缩嫌疑
_ENTROPY_STRUCTURED_THRESHOLD = 0.80  # 低于此值 → 结构化数据节特征
_REPETITION_FACTOR = 0.15       # 每多一次重复的置信度衰减系数
_CROSS_UNIT_BONUS = 0.15        # 跨编译单元传播加成
_CONF_MIN = 0.05
_CONF_MAX = 0.98


def score_hit(misuse,
              api_proximity: float = 0.0,
              region_entropy: float = 0.5,
              repetition_count: int = 1,
              cross_unit: bool = False,
              aggregate: bool = False) -> Dict[str, float]:
    """计算单个模式命中的启发式置信度.

    参数:
      misuse:          crypto_misuse.Misuse (需含 severity 字段)
      api_proximity:   [0,1] 上下游加密 API 邻近度
      region_entropy:  [0,1] 命中点邻域归一化香农熵
      repetition_count: 同常量值在文件内出现次数 (≥1)
      cross_unit:      是否在其它编译单元出现
      aggregate:       是否为无单点锚定的聚合命中

    返回:
      包含最终置信度及各证据分量的字典, 供上层记录与调试。
    """
    sev = getattr(misuse, 'severity', 'MEDIUM')
    base = SEVERITY_BASE.get(sev, 0.5)

    # (2) API 邻近度权重
    if aggregate:
        api_w = 0.7
    elif api_proximity <= 0.0:
        api_w = _API_WEIGHT_NO_CONTEXT
    elif api_proximity >= 1.0:
        api_w = _API_WEIGHT_MAX
    else:
        api_w = 0.6 + 0.45 * api_proximity

    # (3) 邻域熵权重
    if region_entropy > _ENTROPY_RANDOM_THRESHOLD and not aggregate:
        ent_w = 0.6                       # 高熵邻域 → 随机巧合/压缩数据
    elif region_entropy < _ENTROPY_STRUCTURED_THRESHOLD:
        ent_w = 1.0                       # 结构化数据节 → 常量特征
    else:
        ent_w = 0.85

    # (4) 重复度惩罚: 出现越多, 越像查表/测试向量
    rep_w = 1.0 / (1.0 + _REPETITION_FACTOR * max(0, repetition_count - 1))

    conf = base * api_w * ent_w * rep_w
    if cross_unit:
        conf += _CROSS_UNIT_BONUS
    conf = max(_CONF_MIN, min(_CONF_MAX, conf))

    return {
        'confidence': round(conf, 3),
        'base': round(base, 3),
        'api_proximity': round(api_proximity, 3),
        'region_entropy': round(region_entropy, 3),
        'repetition_count': int(repetition_count),
        'cross_unit': bool(cross_unit),
        'aggregate': bool(aggregate),
    }


def adjust_with_llm(heuristic_conf: float, verdict: str) -> float:
    """LLM 判定对启发式置信度的调整规则.

    设计意图: LLM 仅提供方向性证据, 不做绝对值重估 —
      confirmed  +0.15 (上限 0.98);
      rejected  ×0.35 (大幅下调, 消除假阳性);
      uncertain/heuristic_only  不变。
    """
    if verdict == 'confirmed':
        return max(_CONF_MIN, min(_CONF_MAX, heuristic_conf + 0.15))
    if verdict == 'rejected':
        return max(_CONF_MIN, min(_CONF_MAX, heuristic_conf * 0.35))
    return heuristic_conf
