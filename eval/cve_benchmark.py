"""
用CVE样本C源码 (模拟反编译伪代码) 运行完整堆溢出管线并生成量化报告。

反编译输出 ≈ 简化C代码，直接用C源码作为管线的反编译输入。
"""

import json
import os
import re
import sys
import time
import textwrap
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(BASE_DIR, 'tests', 'cve_samples')
OUTPUT_PATH = os.path.join(BASE_DIR, 'eval', 'cve_pipeline_results.json')


# 将C源码转换为简化的伪代码IR行

def _split_multi_declarations(part: str) -> list:
    """拆分多声明行: char *a = x, *b = y → ['char *a = x', 'char *b = y']。

    仅拆分括号深度为0处的逗号, 避免误拆函数参数。
    若无需拆分则返回单元素列表。
    """
    # 快速检查: 是否含有 ',' 后跟 '*'? 或 ',' 后跟变量名+赋值?
    if not re.search(r',\s*\*?\s*\w+\s*=', part):
        return [part]
    # 提取类型前缀 (char *, int 等), 用于重建拆分后的声明
    type_prefix = ''
    _type_kw_pat = (r'^(?:const\s+)?(?:unsigned\s+)?'
                    r'(?:uint\d+_t|int\d+_t|size_t|ssize_t|'
                    r'char|int|long|void|double|float|short)\s*\*?\s*')
    m = re.match(_type_kw_pat, part)
    if m:
        type_prefix = m.group(0)
        rest = part[m.end():]
    else:
        rest = part
    # 深度追踪拆分
    sub_parts = []
    depth = 0
    cur = []
    for ch in rest:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        elif ch == ',' and depth == 0:
            sub_parts.append(''.join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if cur:
        sub_parts.append(''.join(cur).strip())
    # 只有一个部分 → 无需拆分
    if len(sub_parts) <= 1:
        return [part]
    # 重建: 第一个部分已有类型前缀, 后续部分加回前缀
    result = []
    for i, sp in enumerate(sub_parts):
        sp = sp.strip()
        if i == 0:
            result.append(type_prefix + sp)  # 第一个: type + var = expr
        else:
            # 后续: 加 type_prefix (不包含 *, 因为 * 已在 sp 中或 sp 开头)
            # 如果 sp 以 * 开头, 去掉首 *
            sp_clean = re.sub(r'^\*\s*', '', sp)
            result.append(type_prefix.rstrip() + ' ' + sp_clean)
    return result

def c_to_pseudo_ir(c_source: str) -> List[str]:
    """将C源码转换为类反编译伪代码的IR行。

    反编译输出特点:
      - 变量已解析: malloc 的返回值绑定到变量 → var = malloc(size)
      - 指针写入: [var + offset] = value 而非 var[offset] = value
      - 无类型声明, 无 cast, 无分号
    """
    # 先处理多语句行: 按 ; 拆分为独立行 (for 循环头例外)
    expanded_lines = []
    in_block_comment = False
    for raw_line in c_source.split('\n'):
        stripped = raw_line.strip()

        # 跟踪 /* */ 块注释
        if '/*' in stripped:
            in_block_comment = True
        if '*/' in stripped:
            in_block_comment = False
            # 移除注释后保留注释外的代码
            stripped = re.sub(r'/\*.*?\*/', '', stripped).strip()
            if not stripped:
                continue
        if in_block_comment:
            continue

        # 跳过预处理、单行注释、空行、大括号
        if not stripped or stripped.startswith('//') or stripped.startswith('#'):
            continue
        if stripped in ('{', '}'):
            continue

        # 跳过以 * 开头的块注释续行
        if stripped.startswith('*'):
            continue

        # for 循环保护: 将 for(init;cond;incr) 中的分号替换为特殊标记,
        # 拆分后再还原, 保持 for 头完整。
        _for_protected = []
        _for_pat = r'\bfor\s*\(([^)]+)\)'
        _for_matches = list(re.finditer(_for_pat, stripped))
        if _for_matches:
            _last_end = 0
            for _fm in _for_matches:
                _for_protected.append(('text', stripped[_last_end:_fm.start()]))
                _for_body = _fm.group(1).replace(';', '\x00FOR_SEMI\x00')
                _for_protected.append(('for', f'for ({_for_body})'))
                _last_end = _fm.end()
            _for_protected.append(('text', stripped[_last_end:]))
        else:
            _for_protected = [('text', stripped)]

        for _kind, _segment in _for_protected:
            if _kind == 'for':
                # for 头保持完整, 直接加入
                expanded_lines.append(_segment)
                continue
            # 按 ; 和 { 拆分多语句行
            if '{' in _segment:
                _segment = re.sub(r'\{', ';{;', _segment)
            parts = _segment.split(';')
            for part in parts:
                part = part.strip()
                if not part or part in ('{', '}'):
                    continue
                # 多声明拆分: char *a = x, *b = y → 拆为独立行
                # 在第一趟中处理, 保持行顺序
                _multi_parts = _split_multi_declarations(part)
                expanded_lines.extend(_multi_parts)

    # 还原 for 循环头中的分号占位符
    expanded_lines = [s.replace('\x00FOR_SEMI\x00', ';') for s in expanded_lines]

    # 类型关键字 (更具体的模式在前, 避免 int 匹配 int16_t 的前缀)
    _type_kw = (r'(?:const\s+)?(?:unsigned\s+)?'
                r'(?:uint\d+_t|int\d+_t|size_t|ssize_t|'
                r'char|int|long|void|double|float|short)')

    lines = []
    for s in expanded_lines:
        # 跳过函数签名行 (void/int/static + funcname + (params))
        if re.match(r'^(?:static\s+)?(?:void|int|long|char|unsigned|size_t|ssize_t|'
                    r'uint\d+_t)\s+\w+\s*\(', s):
            continue

        # 移除前导类型声明
        if re.match(rf'^{_type_kw}\s*\*?\s*\w+\s*=', s):
            s = re.sub(rf'^{_type_kw}\s*\*?\s*', '', s, count=1)

        # 移除无赋值的变量声明
        if re.match(rf'^{_type_kw}\s*\*?\s*\w+\s*$', s):
            continue

        # 跳过 struct/typedef/extern 行
        if re.match(r'^(?:struct|typedef|static|extern)\s', s):
            continue

        # 移除赋值右侧的 cast: "v = (type *)expr" → "v = expr"
        s = re.sub(r'=\s*\((?:const\s+)?(?:unsigned\s+)?\w+\s*\*?\s*\)\s*', '= ', s)

        # 保留含关键操作的行
        keywords = ['malloc', 'calloc', 'realloc', 'free',
                    'strcpy', 'strncpy', 'memcpy', 'memmove', 'memset', 'strncat', 'strcat',
                    'scanf', 'gets', 'printf', 'fprintf', 'sizeof',
                    'if (', 'for (', 'while (',
                    'return']
        has_kw = any(kw in s for kw in keywords)
        has_assign = ' = ' in s or re.search(r'\w\s*=\s*\w', s)

        if not (has_kw or has_assign):
            continue

        lines.append(s)

    return lines


def _load_c_source(dirpath: str) -> str:
    for fname in ['vuln.c', 'main.c', 'exploit.c']:
        path = os.path.join(dirpath, fname)
        if os.path.isfile(path):
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
    return ''


def _classify(dirname: str) -> Tuple[str, str]:
    """分类: 堆溢出相关 → TP; 包含if守卫 → 降权但仍是TP。"""
    dn = dirname.lower()
    if 'fp-' in dn or 'false' in dn or 'fp_' in dn:
        return ('heap_overflow', 'FP')
    return ('heap_overflow', 'TP')


def run_cve_benchmark() -> Dict:
    t0 = time.perf_counter()
    all_results = []

    # 收集所有有C源码的堆溢出样本
    sample_dirs = []
    for dirname in sorted(os.listdir(SAMPLES_DIR)):
        dirpath = os.path.join(SAMPLES_DIR, dirname)
        if not os.path.isdir(dirpath):
            continue
        dn = dirname.lower()
        if not any(k in dn for k in ('heap', 'overflow', 'ho_', 'cve_2015_0235',
                                       'cve_2019_13134', 'cve_2020_10757',
                                       'cve_2023_45871', 'cve_2016_6301', 'cve_21')):
            continue
        c_src = _load_c_source(dirpath)
        if not c_src:
            continue
        sample_dirs.append((dirname, dirpath, c_src))

    # 处理全部样本

    for dirname, dirpath, c_src in sample_dirs:
        vuln_type, ground_truth = _classify(dirname)
        ir_lines = c_to_pseudo_ir(c_src)
        decompiled_text = c_src

        has_candidate = False
        confidence = 0.0
        stage_details = {}

        # 运行完整管线
        try:
            from core.heap_overflow_pipeline import detect_heap_overflows_full
            candidates, stats = detect_heap_overflows_full(
                ir_lines, decompiled_text)
            if candidates:
                has_candidate = True
                confidence = max(c.confidence for c in candidates)
            stage_details = {
                'pipeline_candidates': len(candidates),
                'stage_context': stats.get('stage_context', 0),
                'stage_detect': stats.get('stage_detect', 0),
                'stage_filter': stats.get('stage_filter', 0),
                'stage_gapsbv': stats.get('stage_gapsbv', 0),
                'stage_vfg': stats.get('stage_vfg', 0),
                'stage_enhanced_filter': stats.get('stage_enhanced_filter', 0),
            }
            if 'vfg_details' in stats:
                stage_details['vfg'] = stats['vfg_details']
        except Exception as e:
            stage_details['pipeline_error'] = str(e)

        predicted = 'TP' if has_candidate else 'FP'

        all_results.append({
            'sample': dirname,
            'type': vuln_type,
            'ground_truth': ground_truth,
            'predicted': predicted,
            'confidence': round(confidence, 3),
            'ir_lines': len(ir_lines),
            'stages': stage_details,
        })

    # 指标计算
    tp = sum(1 for r in all_results if r['ground_truth'] == 'TP' and r['predicted'] == 'TP')
    fp = sum(1 for r in all_results if r['ground_truth'] == 'FP' and r['predicted'] == 'TP')
    tn = sum(1 for r in all_results if r['ground_truth'] == 'FP' and r['predicted'] == 'FP')
    fn = sum(1 for r in all_results if r['ground_truth'] == 'TP' and r['predicted'] == 'FP')

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    elapsed = round((time.perf_counter() - t0) * 1000, 1)

    report = {
        'title': 'BinMind CVHOD Pipeline — CVE Sample Benchmark',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'elapsed_ms': elapsed,
        'summary': {
            'total': len(all_results),
            'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1': round(f1, 4),
            'fp_rate': round(fp_rate, 4),
        },
        'samples': all_results,
    }

    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(json.dumps(report['summary'], indent=2))
    print(f'\nSaved: {OUTPUT_PATH}')

    # Print per-sample results
    for r in all_results:
        status = 'MATCH' if r['ground_truth'] == r['predicted'] else 'MISMATCH'
        print(f"  {r['sample']:40s}  GT={r['ground_truth']:3s}  "
              f"PRED={r['predicted']:3s}  conf={r['confidence']:.2f}  "
              f"[{status}]")

    return report


if __name__ == '__main__':
    run_cve_benchmark()
