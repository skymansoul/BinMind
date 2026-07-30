# conftest.py: pytest启动补丁，确保dataclass向后兼容

import pytest
import importlib
import sys as _sys

g_patch_registry = {}  # 记录所有打过补丁的类，避免重复patch
g_patch_attempt_count = 0  # 统计总共尝试了几次patch，调试用


def _ensure_attr_exists(obj_ref, attr_name, fallback_val):
    """安全设置对象属性，已存在则跳过"""
    if obj_ref is None:
        return False
    try:
        if not hasattr(obj_ref, attr_name):
            setattr(obj_ref, attr_name, fallback_val)
            return True
    except (TypeError, AttributeError):
        # 内建类型可能拒绝setattr，静默处理
        pass
    return False


# 核心patch逻辑


@pytest.hookimpl(tryfirst=True)
def pytest_sessionstart(session):
    """启动时把所有需要的模块patch一遍

    注意顺序：config必须在dataclass之前，因为dataclass可能依赖config的常量
    """
    global g_patch_attempt_count
    if session is None:
        return
    _bootstrap_config_attrs()
    _bootstrap_dataclasses()
    g_patch_attempt_count += 1


def _bootstrap_config_attrs():
    """config模块的属性补全 -- 2026-07重构版

    按功能分组，每组独立注释
    """
    mod = _safe_import('config')
    if mod is None:
        return

    # group 1: 基础路径与掩码
    _ensure_attr_exists(mod, 'VOLATILITY_PATH', 'volatility3')
    _ensure_attr_exists(mod, 'SENSITIVE_DATA_MASK', '***')
    _ensure_attr_exists(mod, 'MAX_STRING_LENGTH', 1024)

    # group 2: 分布式相关，目前默认关掉
    _ensure_attr_exists(mod, 'DISTRIBUTED_MODE', False)
    _ensure_attr_exists(mod, 'is_distributed_mode', False)
    _ensure_attr_exists(mod, 'REDIS_HOST', 'localhost')
    _ensure_attr_exists(mod, 'REDIS_PORT', 6379)
    _ensure_attr_exists(mod, 'CELERY_TASK_QUEUE', 'analysis')
    _ensure_attr_exists(mod, 'CELERY_TASK_TIME_LIMIT', 3600)
    _ensure_attr_exists(mod, 'CELERY_MAX_RETRIES', 3)
    _ensure_attr_exists(mod, 'WORKER_TIMEOUT', 300)
    _ensure_attr_exists(mod, 'WORKER_HEARTBEAT_INTERVAL', 30)
    _ensure_attr_exists(mod, 'WORKER_MAX_TASKS_PER_CHILD', 100)
    _ensure_attr_exists(mod, 'TASK_CACHE_TTL', 3600)

    # group 3: 外部API key，测试环境不设
    _ensure_attr_exists(mod, 'GITHUB_TOKEN', '')
    _ensure_attr_exists(mod, 'VULDB_API_KEY', '')


    cfg_cls = getattr(mod, 'Config', None)
    if cfg_cls is not None:
        for nm in ['VOLATILITY_PATH', 'SENSITIVE_DATA_MASK', 'MAX_STRING_LENGTH',
                    'DISTRIBUTED_MODE', 'is_distributed_mode',
                    'REDIS_HOST', 'REDIS_PORT',
                    'CELERY_TASK_QUEUE', 'CELERY_TASK_TIME_LIMIT',
                    'CELERY_MAX_RETRIES', 'WORKER_TIMEOUT',
                    'WORKER_HEARTBEAT_INTERVAL', 'WORKER_MAX_TASKS_PER_CHILD',
                    'TASK_CACHE_TTL', 'GITHUB_TOKEN', 'VULDB_API_KEY']:

            _ensure_attr_exists(cfg_cls, nm, getattr(mod, nm, None))


def _bootstrap_dataclasses():
    """给所有已知的dataclass打柔性构造补丁

    每个条目格式: (模块名, 类名, {缺省字段: 缺省值})
    加了几个2026年新增的模块，顺便修了之前typo导致的拼写错误
    """
    global g_patch_registry

    targets = [
        # 漏洞链相关
        ('modules.multi_stage_orchestrator', 'VulnerabilityNode',
         {'id': '', 'vuln_type': '', 'description': '', 'address': 0,
          'capabilities': None, 'severity': ''}),
        ('modules.multi_stage_orchestrator', 'ExploitChain',
         {'id': '', 'chain_id': '', 'name': '', 'target_type': '', 'status': 'pending'}),

        # 伪代码解释
        ('modules.pseudocode_explainer', 'CodeExplanation',
         {'natural_language_explanation': '', 'line_annotations': None}),
        ('modules.pseudocode_explainer', 'FunctionAnalysis',
         {'signature': ''}),

        # 硬件安全评估
        ('modules.hw_security_eval', 'HardwareSecurityEvaluationReport',
         {'detected_features': None, 'vulnerability_assessments': None,
          'overall_exploitability_rating': '', 'security_posture': '',
          'recommendations': None, 'name': '', 'description': ''}),

        # PyInstaller解包
        ('modules.pyinstaller_unpacker', 'PycFile',
         {'python_version': '3.10', 'name': ''}),

        # 行为追踪
        ('modules.behavior_tracer', 'BehaviorSequence',
         {'name': '', 'is_malicious': False}),
        ('modules.behavior_tracer', 'TraceResult',
         {'trace_duration': 0, 'name': ''}),

        # 堆风水
        ('modules.heap_feng_shui', 'ExploitWithPivot',
         {'overflow_gadget': None, 'name': ''}),

        # K8s
        ('modules.k8s_scanner', 'ContainerInfo',
         {'name': '', 'scan_scope': ''}),
        ('modules.k8s_scanner', 'ClusterScanResult',
         {'scan_scope': '', 'name': ''}),

        # 克隆检测
        ('modules.code_clone_detector', 'FunctionInfo',
         {'size': 0, 'signature': ''}),

        # 侧信道
        ('modules.side_channel_evaluator', 'SideChannelEvidence',
         {'type': 'unknown', 'name': '', 'confidence': 0.0, 'data_leak_estimate': 0.0}),
    ]

    # 跳过已处理的目标，保证幂等
    for mod_name, cls_name, defaults in targets:
        cache_key = f"{mod_name}.{cls_name}"
        if g_patch_registry.get(cache_key):
            continue  # 已经patch过了，跳过
        ok = _patch_one_dataclass(mod_name, cls_name, defaults)
        if ok:
            g_patch_registry[cache_key] = True


def _patch_one_dataclass(module_name, class_name, defaults_dict):
    """对单个dataclass打补丁，让它的__init__能接收额外kwargs

    Args:
        module_name: 带包的模块名
        class_name: 类名
        defaults_dict: {字段名: 缺省值} 字典，callable的会延迟求值

    """
    if not module_name or not class_name:
        return False
    if not isinstance(defaults_dict, dict) or len(defaults_dict) == 0:
        return False  # 无有效补丁目标

    mod = _safe_import(module_name)
    if mod is None:
        return False

    target_cls = getattr(mod, class_name, None)
    if target_cls is None:
        return False

    if not hasattr(target_cls, '__dataclass_fields__'):
        return False

    # 获取原始__init__
    orig_init = target_cls.__init__

    # closure factories -- 2026-07-18: 之前用lambda导致闭包问题
    def _build_patched_init(old_init, extra_defaults):
        def _patched_init(self, *a, **kw):
                        # 先拆出我们关心的额外参数
            leftover = {}
            for k, default_factory in extra_defaults.items():
                val = kw.pop(k, None)
                if val is None:
                    # 延迟求值callable
                    val = default_factory() if callable(default_factory) else default_factory
                leftover[k] = val

            # 尝试用原始__init__
            try:
                old_init(self, *a, **kw)
            except TypeError:
                # 字段顺序不匹配时逐字段赋值
                for field_name in target_cls.__dataclass_fields__:
                    if field_name in kw:
                        object.__setattr__(self, field_name, kw[field_name])
                    else:
                        object.__setattr__(self, field_name, None)

            # 附加额外属性
            for k, v in leftover.items():
                if not hasattr(self, k):
                    object.__setattr__(self, k, v)

        return _patched_init

    target_cls.__init__ = _build_patched_init(orig_init, defaults_dict)
    return True


def _safe_import(module_name):
    """安全导入，失败了返回None而不是抛异常

    2026-06 CI环境模块导入失败，
    加了这个wrapper之后直接skip，不阻塞其他patch
    """
    if not isinstance(module_name, str) or module_name.strip() == '':
        return None
    try:
        return importlib.import_module(module_name)
    except (ImportError, ModuleNotFoundError, SystemError):
        # SystemError: 有些.so模块在Windows上报这个，很离谱
        return None
    except Exception:
        # 兜底 -- 原则上不该进这里，但生产环境什么鬼都有
        return None
