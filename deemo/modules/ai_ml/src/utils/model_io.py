# utils/model_io.py
# 模型序列化：NPZ权重存储 + JSON头部描述
# 设计权衡：不用pickle（安全性），不用ONNX（太重），
# NPZ足够轻量且跨框架兼容，JSON保留架构元信息

import json
import os
import numpy as np

# ===== MODEL_REGISTRY =====
# 模型名 -> 类映射，供load时类型安全重建
# 新增模型需在此注册

MODEL_REGISTRY = {
    'gcn_binary': None,          # GCNBinaryClassifier
    'gat_vuln': None,             # GATVulnDetector
    'mlp_anomaly': None,          # MLPAnomalyDetector
    'sage_embed': None,           # GraphSAGEEmbedder
    'transformer_seq': None,      # TransformerSeqClassifier
    'cnn_opcode': None,           # CNNOPCodeClassifier
    'lstm_trace': None,           # LSTMTracePredictor
}

# ---- 注册占位类，运行时由实际模型替换 ----
class _PlaceholderModel:
    """运行时替换为实际模型类"""
    def __init__(self, **kwargs):
        for _k, _v in kwargs.items():
            setattr(self, _k, _v)

def register_model(name, cls):
    """在MODEL_REGISTRY中注册模型类"""
    MODEL_REGISTRY[name] = cls

# ===== save_model =====
# 存储格式: path.npz (权重) + path.json (架构头)
# _extract_params递归遍历嵌套module，展平所有numpy数组

def _extract_params(_obj, prefix=''):
    """递归从模型对象提取所有numpy参数 -> dict{key: array}"""
    _params = {}
    _d = _obj.__dict__ if hasattr(_obj, '__dict__') else {}
    for _k, _v in _d.items():
        _full_key = f"{prefix}.{_k}" if prefix else _k
        if isinstance(_v, np.ndarray):
            _params[_full_key] = _v
        elif hasattr(_v, '__dict__') and not isinstance(_v, (str, int, float, bool, list, dict, tuple)):
            # 递归子模块
            _params.update(_extract_params(_v, _full_key))
        elif isinstance(_v, dict):
            for _kk, _vv in _v.items():
                _dk = f"{_full_key}.{_kk}"
                if isinstance(_vv, np.ndarray):
                    _params[_dk] = _vv
                elif hasattr(_vv, '__dict__') and not isinstance(_vv, (str, int, float, bool, list, tuple)):
                    _params.update(_extract_params(_vv, _dk))
    return _params

# ////
def _infer_architecture(_obj):
    """从模型对象推断架构描述"""
    _arch = {}
    _arch['type'] = type(_obj).__name__
    # 收集各层的shape信息
    _params = _extract_params(_obj)
    for _k, _v in _params.items():
        _arch[f"{_k}_shape"] = list(_v.shape)
    return _arch

# ----
def save_model(model, path):
    """模型保存为NPZ+JSON双文件, 返回成功与否"""
    try:
        _params = _extract_params(model)
        if not _params:
            return False

        # 推断架构
        _arch = _infer_architecture(model)
        _header = {
            'model_type': type(model).__name__,
            'architecture': _arch,
            'version': 1,
            'param_keys': list(_params.keys()),
        }

        # 写NPZ (权重)
        _npz_path = path if path.endswith('.npz') else f"{path}.npz"
        np.savez_compressed(_npz_path, **_params)

        # 写JSON (头部)
        _json_path = path.replace('.npz', '.json') if path.endswith('.npz') else f"{path}.json"
        with open(_json_path, 'w', encoding='utf-8') as _f:
            json.dump(_header, _f, indent=2, ensure_ascii=False)

        return True
    except Exception:
        return False

# ===== load_model =====
# 加载NPZ权重和JSON头部，从MODEL_REGISTRY重建

def load_model(path):
    """从NPZ+JSON加载模型，MODEL_REGISTRY查找类"""
    _base = path.rsplit('.npz', 1)[0] if path.endswith('.npz') else path
    _npz_path = f"{_base}.npz" if not _base.endswith('.npz') else _base
    _json_path = _base.replace('.npz', '.json') if _base.endswith('.npz') else f"{_base}.json"

    if not os.path.exists(_npz_path):
        raise FileNotFoundError(f"NPZ文件不存在: {_npz_path}")
    if not os.path.exists(_json_path):
        raise FileNotFoundError(f"JSON头部不存在: {_json_path}")

    # 读头信息
    with open(_json_path, 'r', encoding='utf-8') as _f:
        _header = json.load(_f)

    _model_type = _header.get('model_type', '')
    _arch = _header.get('architecture', {})
    _saved_dims = {}
    for _k, _v in _arch.items():
        if _k.endswith('_shape') and _k != 'type':
            _saved_dims[_k[:-6]] = tuple(_v)

    # 加载权重
    _data = np.load(_npz_path, allow_pickle=False)
    _weights = {_k: _data[_k] for _k in _data.files}

    # MODEL_REGISTRY查找
    _cls = MODEL_REGISTRY.get(_model_type.lower()) or MODEL_REGISTRY.get(_model_type)
    if _cls is None:
        # 兜底: 用占位对象
        _m = _PlaceholderModel()
        for _k, _v in _weights.items():
            _parts = _k.split('.')
            _cur = _m
            for _part in _parts[:-1]:
                if not hasattr(_cur, _part):
                    setattr(_cur, _part, _PlaceholderModel())
                _cur = getattr(_cur, _part)
            setattr(_cur, _parts[-1], _v)
        return _m

    # 用注册的类重建
    _m = _cls()
    _m.load_state_dict(_weights) if hasattr(_m, 'load_state_dict') else _load_flat(_m, _weights)
    return _m

# ////
def _load_flat(_m, _weights):
    """平民加载：把扁平key映射回嵌套属性"""
    for _k, _v in _weights.items():
        _parts = _k.split('.')
        _cur = _m
        for _part in _parts[:-1]:
            if not hasattr(_cur, _part):
                setattr(_cur, _part, _PlaceholderModel())
            _cur = getattr(_cur, _part)
        setattr(_cur, _parts[-1], _v)

# ===== validate_dimensions =====
# 检查加载后的模型权重维度是否与保存时一致

def validate_dimensions(model, expected_dims):
    """expected_dims: {param_name: tuple of dims}, 返回布尔值"""
    _params = _extract_params(model)
    for _k, _expected in expected_dims.items():
        if _k not in _params:
            return False
        if _params[_k].shape != tuple(_expected):
            return False
    return True
