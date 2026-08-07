# Created: 2026-05-26 09:29:15
#
# obfuscation_classifier — 多信号混淆技术精确分类器
# 从纯静态特征 (熵 + 段布局 + 导入模式 + 结构异常) 识别具体混淆技术，
# 无需反汇编或 CFG 提取。区别于 Creach Labs。
#
# 分类的混淆技术 (8 类):
#   upx              UPX/ASPack 等标准运行时可解压打包器
#   custom_packer    自定义打包器 (非标准 stub，高熵 + 无已知签名)
#   xor_encoding     单字节 XOR 编码 (可打印比异常 + 密钥模式)
#   string_encryption 字符串加密 (低可打印密度 + 高熵字符串段)
#   import_hiding    导入表隐藏 (API hashing + 无对应导入字符串)
#   control_flow_flat 控制流平坦化 (异常函数密度 + 大量小函数)
#   dead_code_insert  死代码插入 (低 ngram 比 + 正常熵)
#   virtualization    代码虚拟化 (极高函数密度 + 特定 VM stub 模式)
#
# 每类提供:
# 检测信号组合 (多维度阈值)
# 置信度 (0-1)
# 针对性的解混淆策略建议

import math
from typing import Dict, List, Tuple, Optional


# 混淆技术签名库: 每项定义多信号阈值组合
_OBFUSCATION_SIGNATURES = [
    {
        "technique": "upx",
        "description": "UPX/ASPack 标准打包器",
        "signals": {
            "high_entropy_ratio": (0.4, 1.0, 0.25),
            "layout_anomaly": (0.3, 1.0, 0.25),
            "scale_invariant_regions": (1, 10, 0.20),
            "small_import_count": (0, 15, 0.15),
            "section_name_upx": (True, 0.15),
        },
        "deobfuscation": "upx -d 或标准脱壳工具; 入口点位于 stub 末尾的 tail jump",
        "common_sections": ["UPX0", "UPX1", ".aspack", ".adata"],
    },
    {
        "technique": "custom_packer",
        "description": "自定义/私有打包器",
        "signals": {
            "high_entropy_ratio": (0.6, 1.0, 0.30),
            "layout_anomaly": (0.5, 1.0, 0.25),
            "scale_invariant_regions": (2, 20, 0.15),
            "no_known_packer_sig": (True, 0.20),
            "small_import_count": (0, 8, 0.10),
        },
        "deobfuscation": "动态执行至 OEP + 内存 dump; 或基于熵梯度的层剥离 (见 entropy_gradient_profiler)",
    },
    {
        "technique": "xor_encoding",
        "description": "单字节/简单 XOR 编码",
        "signals": {
            "xor_obfuscation_likely": (True, 0.40),
            "high_entropy_ratio": (0.2, 0.9, 0.20),
            "printable_ratio": (0.2, 0.55, 0.25),
            "layout_anomaly": (0.0, 0.4, 0.15),
        },
        "deobfuscation": "暴力单字节 XOR 解密; 若多字节则用 known-plaintext 攻击 (PE header 已知)",
    },
    {
        "technique": "string_encryption",
        "description": "编译时/运行时字符串加密",
        "signals": {
            "string_density": (0.0, 0.01, 0.30),
            "high_entropy_ratio": (0.3, 1.0, 0.20),
            "dangerous_imports_present": (True, 0.15),
            "api_string_gap": (0.4, 1.0, 0.35),
        },
        "deobfuscation": "动态 hook 字符串解密函数; 静态: 定位 decrypt_routine 的交叉引用并模拟执行",
    },
    {
        "technique": "import_hiding",
        "description": "导入表隐藏 (API hashing + 动态解析)",
        "signals": {
            "api_hashing_likely": (True, 0.45),
            "small_import_count": (0, 5, 0.25),
            "anomalous_import_names": (3, 100, 0.15),
            "hash_density": (0.3, 1.0, 0.15),
        },
        "deobfuscation": "动态: API monitor/hook 记录解析结果; 静态: 识别哈希函数并暴力常见 API 哈希表",
    },
    {
        "technique": "control_flow_flat",
        "description": "控制流平坦化 (CFF/OLLVM)",
        "signals": {
            "function_density": (400, 10000, 0.35),
            "code_section_ratio": (0.5, 0.95, 0.20),
            "high_entropy_ratio": (0.0, 0.3, 0.15),
            "layout_anomaly": (0.0, 0.5, 0.15),
            "import_surface_normal": (True, 0.15),
        },
        "deobfuscation": "符号执行恢复原始控制流; MiASM/Triton 脚本去除 dispatcher 并重组基本块",
    },
    {
        "technique": "dead_code_insert",
        "description": "死代码/垃圾指令插入",
        "signals": {
            "unique_ngram_ratio": (0.0, 0.01, 0.35),
            "function_density": (200, 2000, 0.25),
            "high_entropy_ratio": (0.0, 0.25, 0.20),
            "layout_anomaly": (0.0, 0.3, 0.20),
        },
        "deobfuscation": "NOP sled 清除 + 死代码消除优化 pass; 识别无副作用的指令序列",
    },
    {
        "technique": "virtualization",
        "description": "代码虚拟化 (VMProtect/Themida)",
        "signals": {
            "function_density": (800, 50000, 0.25),
            "scale_invariant_regions": (3, 50, 0.20),
            "small_import_count": (0, 5, 0.15),
            "high_entropy_ratio": (0.5, 1.0, 0.20),
            "layout_anomaly": (0.4, 1.0, 0.20),
        },
        "deobfuscation": "VM handler 逆向 + lifter 模拟; 针对具体 VMProtect/Themida 版本的专用 devirtualizer",
    },
]


def _signal_score(value: float, lo: float, hi: float, weight: float) -> float:
    """线性插值评分: value 在 [lo, hi] 内线性映射到 [0, weight]。
    开区间支持: lo=-1 表示"无下限"，hi=inf 表示"无上限"时使用 sigmoid。
    """
    if lo == -1 and hi == float("inf"):
        return value * weight
    _clipped = max(lo, min(hi, value))
    if hi == lo:
        return weight if value >= lo else 0.0
    return (_clipped - lo) / (hi - lo) * weight


def _bool_score(condition: bool, weight: float) -> float:
    return weight if condition else 0.0


def classify_obfuscation(
    entropy_profile: Dict = None,
    section_info: Dict = None,
    import_info: Dict = None,
    binary_info: Dict = None,
    evasion_result: Dict = None,
    fingerprint: Dict = None,
    mrem_result: Dict = None,
) -> Dict:
    """多信号混淆技术分类主入口。

    输入各分析模块的输出，返回每种已知混淆技术的匹配得分及综合判定。

    返回:
    - matches: 按置信度降序的所有技术匹配
    - top_match: 最可能的混淆技术
    - multi_technique: 是否检测到多种混淆 (分层混淆)
    - layered_obfuscation: 若 ≥2 项 score > 0.35 → 多层混淆
    - recommendations: 针对性解混淆建议
    """
    # 提取所有需要的信号值
    _ep = entropy_profile or {}
    _si = section_info or {}
    _ii = import_info or {}
    _bi = binary_info or {}
    _ev = evasion_result or {}
    _fp = fingerprint or {}
    _mr = mrem_result or {}

    _signals = {
        "high_entropy_ratio": _ep.get("high_window_ratio",
            _bi.get("entropy", {}).get("high_window_ratio", 0.0)),
        "layout_anomaly": _fp.get("section_entropy", {}).get("layout_anomaly_score",
            _bi.get("suspicious_packing", 0.0) * 0.5),
        "scale_invariant_regions": len(_mr.get("scale_invariant_regions", [])),
        "small_import_count": sum(len(v) for v in _ii.get("all_imports", {}).values()) if isinstance(
            _ii.get("all_imports"), dict) else 0,
        "section_name_upx": any(
            s.get("name", "") in ("UPX0", "UPX1", ".aspack")
            for s in _bi.get("sections", []) if isinstance(s, dict)),
        "no_known_packer_sig": not any(
            s.get("name", "") in ("UPX0", "UPX1", ".aspack", ".adata")
            for s in _bi.get("sections", []) if isinstance(s, dict)),
        "xor_obfuscation_likely": _bi.get("xor_obfuscation", {}).get(
            "xor_obfuscation_likely", _ev.get("anti_analysis", {}).get("score", 0.0) > 0.2),
        "printable_ratio": 1.0 - _ep.get("high_window_ratio", 0.0),
        "string_density": _ev.get("entropy_string_mismatch", {}).get("string_density", 0.01),
        "dangerous_imports_present": len(_ii.get("dangerous_functions", [])) > 0,
        "api_string_gap": _ev.get("string_api_gap", {}).get("score", 0.0),
        "api_hashing_likely": _bi.get("api_hashing", {}).get("likely_api_hashing", False),
        "anomalous_import_names": _ii.get("anomalous_count",
            _bi.get("import_anomaly", {}).get("anomalous_count", 0)),
        "hash_density": _bi.get("api_hashing", {}).get("hash_density", 0.0),
        "function_density": len(_bi.get("functions", [])) / max(
            len(_bi.get("sections", [])), 1),
        "code_section_ratio": _fp.get("section_entropy", {}).get("code_ratio", 0.4),
        "import_surface_normal": len(_ii.get("dangerous_functions", [])) < 3,
        "unique_ngram_ratio": _ep.get("unique_ngram_ratio",
            _bi.get("ngram_fingerprint", {}).get("unique_ngram_ratio", 0.1)),
    }

    _matches = []
    for _sig in _OBFUSCATION_SIGNATURES:
        _score = 0.0
        _signal_details = {}
        for _sname, _spec in _sig["signals"].items():
            _val = _signals.get(_sname, 0)
            if len(_spec) == 3:
                _lo, _hi, _w = _spec
                if isinstance(_val, bool):
                    _s = _bool_score(_val, _w)
                else:
                    _s = _signal_score(float(_val), float(_lo), float(_hi), _w)
            elif len(_spec) == 2:
                _cond, _w = _spec
                _s = _bool_score(_val == _cond if isinstance(_cond, bool) else _val >= _cond, _w)
            else:
                _s = 0.0
            _score += _s
            _signal_details[_sname] = {"value": _val, "score": round(_s, 4)}

        # 检查已知段名: 若段名匹配 → 大幅提高置信度
        _sec_names = {s.get("name", "") for s in _bi.get("sections", []) if isinstance(s, dict)}
        if _sig.get("common_sections") and (_sec_names & set(_sig["common_sections"])):
            _score += 0.20

        _matches.append({
            "technique": _sig["technique"],
            "description": _sig["description"],
            "confidence": round(min(_score, 1.0), 4),
            "deobfuscation_strategy": _sig["deobfuscation"],
            "signal_details": _signal_details,
        })

    _matches.sort(key=lambda x: x["confidence"], reverse=True)
    _top = _matches[0] if _matches else None

    # 多层混淆检测
    _multi = [m for m in _matches if m["confidence"] > 0.35]
    _layered = len(_multi) >= 2

    return {
        "matches": _matches,
        "top_match": _top,
        "multi_technique_detected": _layered,
        "high_confidence_matches": [m for m in _matches if m["confidence"] > 0.35],
        "layered_obfuscation": _layered,
        "recommendations": [
            {"technique": m["technique"], "strategy": m["deobfuscation_strategy"]}
            for m in _matches[:3] if m["confidence"] > 0.20
        ],
        "summary": (_top["description"] if _top and _top["confidence"] > 0.30
                     else "未检测到已知混淆技术" if not _layered
                     else f"检测到 {len(_multi)} 层混淆: {', '.join(m['technique'] for m in _multi)}"),
    }
