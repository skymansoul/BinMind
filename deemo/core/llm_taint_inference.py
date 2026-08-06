# LLM辅助污点源/汇自动推断 — 基于 LATTE (Ant Group, 2025) 思路
# 论文: "Harnessing the Power of LLM to Support Binary Taint Analysis", arXiv:2401.01625
# 核心改进: 用LLM分析反编译伪代码, 自动识别非标准库的输入源和危险汇聚点,
# 解决纯正则匹配对定制化API/间接输入路径的漏检问题。
# LLM不可用时降级为纯正则推断, 不阻塞主流程。

from __future__ import annotations

import json
import logging
import re
from typing import List, Optional

from core.detection_shared import TaintSource, TaintSink

_log = logging.getLogger(__name__)

# 内置正则fallback — LLM不可用或超时时的降级策略
_FALLBACK_SOURCE_PATTERNS = [
    r'\b(read|recv|recvfrom|recvmsg|fgets|fread|scanf|getenv|getenv_s)\s*\(',
    r'\b(ReadFile|WSARecv|InternetReadFile|RegQueryValue)\s*\(',
    r'\b(recv|read|input)\s*\(\s*[^)]*\)',  # 通用模式
]

_FALLBACK_SINK_PATTERNS = [
    r'\b(system|exec[lv]?[pe]?|popen|CreateProcess|ShellExecute)\s*\(',
    r'\b(strcpy|strcat|sprintf|vsprintf|memcpy|gets)\s*\(',
    r'\b(send|write|fprintf|printf)\s*\(',
]

_SOURCE_INFERENCE_PROMPT = """分析以下反编译的C代码, 识别所有外部输入源(污点源)。
返回JSON数组, 每项含: name(变量/参数名), kind(函数名如recv/read/自定义API), lineno(行号), reason(一句话理由)。
只列出确实从外部接收数据的调用点(网络、文件、环境变量、IPC消息、共享内存等)。不要列出内部赋值或常量。
若无外部输入源, 返回空数组[]。

反编译代码:
{code}

仅输出JSON, 无markdown包裹。"""

_SINK_INFERENCE_PROMPT = """分析以下反编译的C代码, 识别所有危险操作汇聚点(污点汇聚点)。
返回JSON数组, 每项含: name(变量/参数名), kind(函数名如system/strcpy/memcpy/printf), lineno(行号), reason(一句话理由)。
关注: 命令执行、内存复制(可能溢出)、格式化字符串、文件写入、权限提升操作。
不要列出无害的内部辅助函数调用。若无危险汇聚点, 返回空数组[]。

反编译代码:
{code}

仅输出JSON, 无markdown包裹。"""


def _regex_infer_sources(pseudocode: str, func_name: str) -> List[dict]:
    """正则降级: 模式匹配推断污点源"""
    sources = []
    for lineno, line in enumerate(pseudocode.split('\n'), start=1):
        for pat in _FALLBACK_SOURCE_PATTERNS:
            m = re.search(pat, line, re.IGNORECASE)
            if m:
                # 提取被赋值的左值变量
                assign_m = re.match(r'(\w[\w.]*)\s*=', line.strip())
                var_name = assign_m.group(1) if assign_m else 'unknown'
                sources.append({
                    'name': var_name,
                    'kind': m.group(1),
                    'lineno': lineno,
                    'reason': f'pattern match: {m.group(0)[:60]}'
                })
                break
    return sources


def _regex_infer_sinks(pseudocode: str, func_name: str) -> List[dict]:
    """正则降级: 模式匹配推断污点汇聚点"""
    sinks = []
    for lineno, line in enumerate(pseudocode.split('\n'), start=1):
        for pat in _FALLBACK_SINK_PATTERNS:
            m = re.search(pat, line, re.IGNORECASE)
            if m:
                args_str = line[line.find('(')+1:line.rfind(')')] if '(' in line else ''
                args = [a.strip() for a in args_str.split(',')] if args_str else []
                sinks.append({
                    'name': args[0] if args else 'unknown',
                    'kind': m.group(1),
                    'lineno': lineno,
                    'reason': f'pattern match: {m.group(0)[:60]}'
                })
                break
    return sinks


def infer_taint_sources(
    pseudocode: str,
    func_name: str,
    llm_timeout: float = 5.0
) -> List[TaintSource]:
    """推断函数内的污点源。
    优先走LLM推断, 不可用时降级为正则模式匹配。
    """
    sources_raw = []
    used_llm = False

    try:
        from core.ai_backends import query_llm
        prompt = _SOURCE_INFERENCE_PROMPT.format(code=pseudocode[:8000])
        resp = query_llm(
            system='你是二进制安全分析专家。只输出JSON。',
            user=prompt,
            temperature=0.1,
            max_tokens=1024,
        )
        # 移除可能的markdown包裹
        resp = resp.strip()
        if resp.startswith('```'):
            resp = resp.split('\n', 1)[1].rsplit('\n```', 1)[0]
        sources_raw = json.loads(resp)
        used_llm = True
        _log.debug('LLM inferred %d sources for %s', len(sources_raw), func_name)
    except Exception:
        _log.debug('LLM inference failed for %s, falling back to regex', func_name)
        sources_raw = _regex_infer_sources(pseudocode, func_name)

    result = []
    for s in sources_raw:
        result.append(TaintSource(
            kind=s.get('kind', 'unknown'),
            var_name=s.get('name', 'unknown'),
            func_name=func_name,
            address=s.get('lineno', 0),
        ))
    # LLM推断标记: 存入不存在的address高位作为元数据 (bit 63)
    if used_llm:
        for s in result:
            s.address = s.address | (1 << 63) if s.address else (1 << 63)
    return result


def infer_taint_sinks(
    pseudocode: str,
    func_name: str,
    llm_timeout: float = 5.0
) -> List[TaintSink]:
    """推断函数内的污点汇聚点(Sink)。
    优先走LLM推断, 不可用时降级为正则模式匹配。
    """
    sinks_raw = []
    used_llm = False

    try:
        from core.ai_backends import query_llm
        prompt = _SINK_INFERENCE_PROMPT.format(code=pseudocode[:8000])
        resp = query_llm(
            system='你是二进制安全分析专家。只输出JSON。',
            user=prompt,
            temperature=0.1,
            max_tokens=1024,
        )
        resp = resp.strip()
        if resp.startswith('```'):
            resp = resp.split('\n', 1)[1].rsplit('\n```', 1)[0]
        sinks_raw = json.loads(resp)
        used_llm = True
        _log.debug('LLM inferred %d sinks for %s', len(sinks_raw), func_name)
    except Exception:
        _log.debug('LLM sink inference failed for %s, falling back to regex', func_name)
        sinks_raw = _regex_infer_sinks(pseudocode, func_name)

    result = []
    for s in sinks_raw:
        result.append(TaintSink(
            kind=s.get('kind', 'unknown'),
            var_name=s.get('name', 'unknown'),
            func_name=func_name,
            address=s.get('lineno', 0),
        ))
    if used_llm:
        for s in result:
            s.address = s.address | (1 << 63) if s.address else (1 << 63)
    return result


def augment_taint_tracking(
    pseudocode: str,
    func_name: str,
    existing_sources: List[TaintSource],
    existing_sinks: List[TaintSink],
) -> tuple[List[TaintSource], List[TaintSink]]:
    """用LLM推断结果增强现有正则source/sink列表。
    不替换已有条目, 仅追加LLM发现的新条目并去重。
    去重依据: (name, kind, line) 三元组。

    返回: (merged_sources, merged_sinks)
    """
    seen_src = {(s.var_name, s.kind, s.address & ~(1 << 63)) for s in existing_sources}
    seen_snk = {(s.var_name, s.kind, s.address & ~(1 << 63)) for s in existing_sinks}

    llm_sources = infer_taint_sources(pseudocode, func_name)
    llm_sinks = infer_taint_sinks(pseudocode, func_name)

    new_src = [s for s in llm_sources
               if (s.var_name, s.kind, s.address & ~(1 << 63)) not in seen_src]
    new_snk = [s for s in llm_sinks
               if (s.var_name, s.kind, s.address & ~(1 << 63)) not in seen_snk]

    if new_src:
        _log.info('%s: LLM added %d new sources', func_name, len(new_src))
    if new_snk:
        _log.info('%s: LLM added %d new sinks', func_name, len(new_snk))

    return existing_sources + new_src, existing_sinks + new_snk
