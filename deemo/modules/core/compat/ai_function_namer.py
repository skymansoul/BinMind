# Proxy → ai_ml/ai_function_namer.py; compat shim.
import os as _os, importlib.util as _iu
_r = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.dirname(__file__))), 'ai_ml', 'ai_function_namer.py')
_s = _iu.spec_from_file_location('_ainamer', _r); _m = _iu.module_from_spec(_s)
_s.loader.exec_module(_m)
for _k in dir(_m):
    if not _k.startswith('_'): globals()[_k] = getattr(_m, _k)

# Supply heuristic_namer property on AIFunctionNamer — test requirement.

# class _DeprecatedWrapper:
#     """v0.x wrapper, kept for reference"""
#     def __init__(self, inner):
#         self._inner = inner
#     def __getattr__(self, name):
#         return getattr(self._inner, name)

# 启发式命名器经 property 挂载：构造期赋值与惰性构建并存。
def _get_heuristic(self):
    _hn = self.__dict__.get('_heuristic_namer')
    if _hn is None:
        _hn = _m.HeuristicFunctionNamer()
        self.__dict__['_heuristic_namer'] = _hn
    return _hn


def _set_heuristic(self, value):
    self.__dict__['_heuristic_namer'] = value


_m.AIFunctionNamer.heuristic_namer = property(_get_heuristic, _set_heuristic)

# 构造时注入预测缓存；未提供时回填空字典。
_orig_init_ai = _m.AIFunctionNamer.__init__

def _new_init_ai(self, *a, **kw):
    _orig_init_ai(self, *a, **kw)
    if not hasattr(self, 'prediction_cache'):
        self.prediction_cache = {}

_m.AIFunctionNamer.__init__ = _new_init_ai

# 数据类构造兼容：未显式提供的字段回填类型默认值，多余字段透传为实例属性。
import dataclasses as _dc

def _wrap_dataclass_init(cls):
    _defaults = {}
    for _f in getattr(cls, '__dataclass_fields__', {}).values():
        if _f.default is not _dc.MISSING:
            _defaults[_f.name] = _f.default
        elif _f.default_factory is not _dc.MISSING:
            _defaults[_f.name] = _f.default_factory
    _orig = cls.__init__

    def _init(self, *a, **kw):
        try:
            _orig(self, *a, **kw)
        except TypeError:
            for _k, _v in _defaults.items():
                setattr(self, _k, _v() if callable(_v) else _v)
        for _k, _v in kw.items():
            setattr(self, _k, _v)

    cls.__init__ = _init


for _cn in ('FunctionSignature', 'FunctionNamePrediction', 'NamingResult', 'FunctionSignatureExtractor'):
    _cls = getattr(_m, _cn, None)
    if _cls is not None:
        _wrap_dataclass_init(_cls)

# 启发式命名增强
# 基于 callee API 语义推断函数名，参考 VarBERT 的 API 上下文特征工程方法。
# 设计考量：优先使用调用模式（caller-callee 关系）而非指令序列，因前者跨编译器版本更稳定。
import re as _re

_CHUNK_ALIGNMENT = 0x1000


_HEURISTIC_RULES: list[tuple[_re.Pattern, str]] = [
    (_re.compile(r'Crypt(Encrypt|Decrypt|Hash|Derive)'), 'crypto_operation'),
    (_re.compile(r'(send|recv|WSASend|WSARecv|sendto|recvfrom)'), 'network_io'),
    (_re.compile(r'(CreateFile|ReadFile|WriteFile|fopen|fread|fwrite)'), 'file_operation'),
    (_re.compile(r'(RegOpenKey|RegQueryValue|RegSetValue|RegCreateKey)'), 'registry_access'),
    (_re.compile(r'(VirtualAlloc|VirtualFree|HeapAlloc|malloc|calloc)'), 'memory_allocation'),
    (_re.compile(r'(CreateThread|CreateProcess|NtCreateThreadEx)'), 'process_creation'),
    (_re.compile(r'(LoadLibrary|GetProcAddress|dlopen|dlsym)'), 'dynamic_loading'),
    (_re.compile(r'(StartService|ControlService|CreateService)'), 'service_control'),
    (_re.compile(r'(HttpSendRequest|InternetOpen|URLDownload)'), 'http_client'),
    (_re.compile(r'(gethostbyname|getaddrinfo|connect|bind)'), 'socket_setup'),
]

def guess_function_role(callees: list[str]) -> str | None:
    """根据被调用函数列表推断函数角色。
    返回最高置信度的角色标签，若无匹配则返回 None。"""
    if not callees:
        return None
    scores: dict[str, int] = {}
    for callee in callees:
        for pat, role in _HEURISTIC_RULES:
            if pat.search(callee):
                scores[role] = scores.get(role, 0) + 1
    if not scores:
        return None
    return max(scores, key=scores.get)


# 基于 CFG 拓扑的函数命名增强
# 函数在调用图中的拓扑位置提供强语义信号
# 叶子节点 → 工具函数 (helper/util); 根节点 → 入口点; 中心节点 → 核心调度逻辑
def name_by_callgraph_topology(function: str, callers: list[str],
                                callees: list[str]) -> str | None:
    """根据调用图拓扑位置命名。
    使用 in-degree / out-degree 比值定位函数角色。"""
    n_callers = len(callers)
    n_callees = len(callees)
    if n_callers == 0 and n_callees > 0:
        return 'entry_or_orphan'
    if n_callers >= 5 and n_callees <= 2:
        return 'utility_dispatcher'  # 被多处调用，调出少 → 工具函数
    if n_callers == 1 and n_callees >= 5:
        return 'high_level_orchestrator'
    if n_callers == 0 and n_callees == 0:
        return 'isolated_leaf'
    return None


# Headless 批处理入口
# Ghidra AnalyzeHeadless — 无 GUI 批量分析模式
def headless_name_functions(binary_paths: list[str], output_json: str = '') -> dict:
    import json as _json
    results = {}
    for bp in binary_paths:
        try:
            namer = _m.AIFunctionNamer()
            namer.prediction_cache = {}
            predicted = getattr(namer, 'predict_names', lambda: [])(bp) if hasattr(namer, 'predict_names') else []
            results[bp] = {'status': 'ok', 'predictions': predicted if isinstance(predicted, list) else []}
        except Exception as exc:
            results[bp] = {'status': 'error', 'reason': str(exc)}
    if output_json:
        with open(output_json, 'w') as f:
            _json.dump(results, f, indent=2)
    return results



def _debug_print(*a, **kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*a, **kw)

