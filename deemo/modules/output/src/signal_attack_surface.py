"""
信号处理器攻击面映射 — sigaction 注册×异步信号安全×可达危险函数。

问题定义:
  信号处理器在异步上下文中执行，打破了正常的控制流假设。
  Trail of Bits 在 regreSSHion 分析中
  用 Multiplier 手工追踪信号处理器可达路径。本模块提供第一个
  自动化的信号攻击面评分模型。

  风险三维:
    1. 处理器函数自身的复杂度 — 高 CC 的处理器更可能有缺陷
    2. 可达的异步不安全函数 — free/malloc/printf 在信号上下文中危险
    3. 信号类型 — SIGALRM/SIGIO 高频触发 > SIGUSR1 手动触发

  特殊风险: SIGALRM + 堆操作 → 经典竞争条件。
  SIGSEGV/SIGBUS 处理器尤其危险 — 它们在最坏的时机被调用。

  Trail of Bits CVE-2024-6387 analysis: 手工路径追踪
  CERT C SIG30-C: 信号处理器中仅调用异步安全函数
  POSIX async-signal-safe 函数列表

修改记录:
  2024-09-27 15:33 - 初始版本，信号类型×可达函数×处理器复杂度的三维模型
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

# 信号 → 风险权重 (触发频率 + 上下文危险度)
_SIGNAL_RISK: Dict[str, float] = {
    'SIGALRM': 0.90,   # 定时器 — 高频+不可预测时机
    'SIGIO': 0.80,     # 异步 I/O — 高频
    'SIGURG': 0.70,    # 紧急数据 — 中等频率
    'SIGCHLD': 0.55,   # 子进程状态 — 中等频率
    'SIGPROF': 0.65,   # 性能分析定时器
    'SIGVTALRM': 0.65, # 虚拟定时器
    'SIGXCPU': 0.50,   # CPU 时间超限
    'SIGXFSZ': 0.40,   # 文件大小超限
    'SIGWINCH': 0.30,  # 窗口大小变化 — 低频
    'SIGPIPE': 0.35,   # 管道破裂 — 中等
    'SIGUSR1': 0.25,   # 用户自定义 — 手动触发
    'SIGUSR2': 0.25,
    'SIGTERM': 0.20,   # 终止 — 仅调用一次
    'SIGINT': 0.20,    # 中断 — 仅调用一次
    'SIGHUP': 0.20,    # 挂断 — 仅调用一次
    'SIGQUIT': 0.15,
    'SIGSEGV': 0.95,   # 段错误 — 在崩溃瞬间调用, 内存状态不可靠
    'SIGBUS': 0.95,    # 总线错误 — 同理
    'SIGABRT': 0.55,   # 异常终止
    'SIGFPE': 0.65,    # 浮点异常
    'SIGILL': 0.60,    # 非法指令
    'SIGTRAP': 0.45,   # 跟踪/断点
    'SIGSYS': 0.60,    # 非法系统调用
}

# 异步信号不安全函数 (CERT C SIG30-C 子集 + 常见危险函数)
_ASYNC_UNSAFE: FrozenSet[str] = frozenset({
    'malloc', 'free', 'realloc', 'calloc',
    'printf', 'fprintf', 'sprintf', 'snprintf', 'vsprintf',
    'puts', 'fputs', 'fwrite', 'fread',
    'syslog', 'openlog', 'closelog',
    'getpwnam', 'getpwuid', 'gethostbyname', 'getaddrinfo',
    'localtime', 'asctime', 'ctime',
    'setlocale', 'pthread_mutex_lock', 'pthread_mutex_unlock',
    'exit', '_exit', 'abort',
    'longjmp', 'siglongjmp',
    'dlopen', 'dlsym', 'dlclose',
    'backtrace', 'backtrace_symbols',
})

# 信号注册函数
_SIGNAL_REGISTER_FUNCS = frozenset({
    'signal', 'sigaction', 'sigvec', 'bsd_signal',
    'ssh_signal', 'ssh_signal_register',
})

@dataclass
class SignalRisk:
    """单个信号处理器的风险评估。"""
    signal_name: str
    handler_function: str
    signal_weight: float           # 信号风险权重
    handler_complexity_risk: float # 处理器复杂度
    unsafe_reachables: List[str]   # 可达的非安全函数
    unsafe_count: int
    composite_risk: float          # 综合风险 0-10
    escalation_potential: str = ''

def _detect_signal_usage(imports: List[str]) -> Dict[str, List[str]]:
    """
    从导入表检测信号注册 → 返回 {signal_func: [matching_imports]}。
    """
    found: Dict[str, List[str]] = {}
    for imp in imports:
        norm = imp.lower().lstrip('_').replace('__imp_', '')
        for sig_func in _SIGNAL_REGISTER_FUNCS:
            if sig_func in norm:
                found.setdefault(sig_func, []).append(imp)
    return found

def _detect_unsafe_reachables(
    handler_name: str,
    call_graph: Optional[Dict[str, Set[str]]] = None,
    imports: Optional[List[str]] = None,
) -> List[str]:
    """
    从调用图检测处理器可达的非安全函数。

    无调用图时回退到导入表匹配 — 假设处理器可能调用任何导入。
    """
    if call_graph and handler_name in call_graph:
        reachable = set()
        stack = [handler_name]
        visited = set()
        while stack:
            f = stack.pop()
            if f in visited:
                continue
            visited.add(f)
            callees = call_graph.get(f, set())
            for c in callees:
                if c.lower() in _ASYNC_UNSAFE:
                    reachable.add(c)
                stack.append(c)
        return list(reachable)

    # 无调用图: 保守假设 — 所有非安全导入都可能被调用
    if imports:
        return [i for i in imports if i.lower().lstrip('_') in _ASYNC_UNSAFE]

    return []

def score_signal_risk(
    signal_name: str,
    handler_function: str,
    handler_cyclomatic_complexity: int = 1,
    call_graph: Optional[Dict[str, Set[str]]] = None,
    imports: Optional[List[str]] = None,
) -> SignalRisk:
    """
    评估单个信号处理器的攻击面风险。

    返回 SignalRisk (0-10 composite_risk)。
    """
    sw = _SIGNAL_RISK.get(signal_name.upper(), 0.30)

    # 复杂度风险: CC>20 → 高风险
    cc = handler_cyclomatic_complexity
    cc_risk = min(cc / 25.0, 1.0) if cc > 3 else 0.1

    unsafe = _detect_unsafe_reachables(handler_function, call_graph, imports)

    # 可达非安全函数的指数贡献
    unsafe_score = 1.0 - math.exp(-len(unsafe) * 1.2) if unsafe else 0.0

    raw = sw * 6.0 + cc_risk * 2.0 + unsafe_score * 2.0
    composite = round(min(raw, 10.0), 1)

    # 提权潜力
    if sw >= 0.90 and unsafe:
        esc = ('high — 高危信号 (SIGSEGV/SIGBUS/SIGALRM) '
               '在不可预测时机调用非安全函数 → 经典竞争条件')
    elif sw >= 0.70 and len(unsafe) >= 2:
        esc = 'medium — 高频信号 + 多个不安全调用'
    elif unsafe:
        esc = 'low — 存在理论风险但触发频率低'
    else:
        esc = 'minimal'

    return SignalRisk(
        signal_name=signal_name.upper(),
        handler_function=handler_function,
        signal_weight=sw,
        handler_complexity_risk=round(cc_risk, 2),
        unsafe_reachables=unsafe,
        unsafe_count=len(unsafe),
        composite_risk=composite,
        escalation_potential=esc,
    )

def signal_surface_summary(
    risks: List[SignalRisk],
    import_evidence: Optional[Dict[str, List[str]]] = None,
) -> Dict[str, Any]:
    """信号攻击面摘要。"""
    if not risks:
        return {'total_handlers': 0, 'signal_registration_detected': False,
                'max_risk': 0, 'high_risk_handlers': []}

    high = [r for r in risks if r.composite_risk >= 6.0]

    return {
        'total_handlers': len(risks),
        'signal_registration_detected': bool(import_evidence),
        'registration_evidence': import_evidence or {},
        'max_risk': max(r.composite_risk for r in risks),
        'high_risk_count': len(high),
        'high_risk_handlers': [
            {'signal': r.signal_name, 'handler': r.handler_function,
             'risk': r.composite_risk, 'unsafe_count': r.unsafe_count,
             'escalation': r.escalation_potential}
            for r in sorted(risks, key=lambda x: x.composite_risk, reverse=True)[:5]
        ],
    }
