"""判定类型与置信度口径 — CACBV 输出的唯一词汇表。

OVERFLOW 与 LIKELY 才进入报告; UNCERTAIN 默认抑制(误报主来源)，
SAFE/FILTERED 由耦合验证或误报过滤器证明后丢弃。
"""


# 判定枚举值
OVERFLOW = 'OVERFLOW'      # 差值为正可证明
LIKELY = 'LIKELY'          # 差值可能为正且无安全信号
UNCERTAIN = 'UNCERTAIN'    # 无法证明且无攻击信号 — 默认不报
SAFE = 'SAFE'              # 差值<=0 可证明
FILTERED = 'FILTERED'      # 被误报过滤器阶段丢弃

# 置信度区间: 阈值统一在此管理
CONF_REPORT_MIN = 0.60     # 低于此值的候选不进入报告
CONF_OVERFLOW = 0.90       # 常量/区间可证明溢出
CONF_LIKELY = 0.72         # 未耦合+无守卫的动态写入
CONF_COUPLED_SAFE = 0.10   # 耦合但未证明安全时残留的权重

SEVERITY_MAP = {
    OVERFLOW: 'Critical',
    LIKELY: 'High',
    UNCERTAIN: 'Low',
    SAFE: 'Info',
    FILTERED: 'Info',
}


def decide(provable_le: bool, provable_gt: bool,
           coupled: bool, guarded: bool) -> tuple:
    """由符号比较结果映射到最终判定。

    规则: 可证明不溢出→SAFE; 可证明溢出→OVERFLOW;
    均不可证→LIKELY(报告)。安全信号已在 coupling_check 前置
    阶段(coupled-delta/guard-subst/aligned-capacity)消费,
    残差到达此处即视为未证否的可疑点。
    """
    if provable_le:
        return SAFE, CONF_OVERFLOW * 0.3
    if provable_gt:
        return OVERFLOW, CONF_OVERFLOW
    return LIKELY, CONF_LIKELY
