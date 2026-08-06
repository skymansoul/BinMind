"""端到端集成测试: 解压代码 -> 所有分析层 -> 结果"""
import sys; sys.path.insert(0, '.')
from core.vuln_analyzer import analyze_all
from core.false_positive_filter import FalsePositiveFilter
from core.const_propagation import SparseConstantPropagation
from core.taint_filter import TaintFilter
from core.interval_analysis import IntervalAnalyzer
from core.ir_normalizer import normalize_ir

decompiled = {
    'test_uaf': 'char *buf = malloc(128);\nfree(buf);\nx = *buf;\nprintf("safe msg");\n',
    'test_fmtstr': 'char *input = read(0, data, 128);\nprintf(input);\nprintf("Hello, %s", name);\n',
}
findings = analyze_all(binary_path='/dev/null', decompiled=decompiled,
                       vuln_types=['heap-corruption', 'format-string'])
filtered = [f for f in findings if f.get('filtered')]
kept = [f for f in findings if not f.get('filtered')]
print(f'End-to-end: {len(findings)} total ({len(kept)} kept, {len(filtered)} filtered)')
for f in findings:
    status = '[FILTERED]' if f.get('filtered') else '[KEPT]   '
    desc = f.get('description', '?')[:70]
    cwe = f.get('cwe', '')
    print(f'  {status} [{cwe}] {desc}')
print('Pipeline OK')
