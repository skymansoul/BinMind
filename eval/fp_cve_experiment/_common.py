"""实验脚本公共设施 — 路径注入与可选依赖导入.

多个基准/绘图脚本重复相同的 sys.path 注入与 ImportError 保护,
集中于此避免逐字复制.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEEMO = os.path.abspath(os.path.join(HERE, '..', '..'))

_HEAP_DIR = os.path.join(DEEMO, 'modules', 'vuln', 'src', 'heap')
_FORMAT_DIR = os.path.join(DEEMO, 'modules', 'vuln', 'src', 'format')


def setup_paths(with_format: bool = False) -> None:
    """注入项目路径: 脚本目录与 vuln 引擎目录.

    with_format=True 时追加 format 引擎目录 (FMT-SAC 脚本)."""
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    if _HEAP_DIR not in sys.path:
        sys.path.insert(0, _HEAP_DIR)
    if with_format and _FORMAT_DIR not in sys.path:
        sys.path.insert(0, _FORMAT_DIR)


def try_import(name: str):
    """可选依赖导入: 缺失时返回 None 而非中断."""
    try:
        return __import__(name)
    except ImportError:
        return None


def list_samples(corpus_dir: str, pattern: str = '*'):
    """遍历语料目录, 返回 [(样本目录, truth_dict)] 已过滤无 truth.json 者."""
    import glob
    import json
    out = []
    for d in sorted(glob.glob(os.path.join(corpus_dir, pattern))):
        t = os.path.join(d, 'truth.json')
        if os.path.isdir(d) and os.path.exists(t):
            with open(t, encoding='utf-8') as f:
                out.append((d, json.load(f)))
    return out


def find_binary(sample_dir: str, exe_name: str):
    """样本目录内定位指定变体二进制, 缺失返回 None."""
    p = os.path.join(sample_dir, exe_name)
    return p if os.path.exists(p) else None
