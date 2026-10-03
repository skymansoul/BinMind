import sys, time, json
sys.path.insert(0, 'C:/Users/Administrator/Desktop/BinMind/deemo')
from modules.analysis.static.tools.heap_overflow_filtered import FilteredHeapOverflowDetector
from modules.analysis.static.tools.format_string_detector import FormatStringDetector
from modules.analysis.static.tools.fmt_spec_analyzer import FormatSpecAnalyzer
from modules.analysis.static.tools.fmt_size_aware import FmtSizeAwareFilter, SizeAwareVerdict
from modules.analysis.static.binary_analysis.uaf_detector import UAFDetector
from modules.analysis.static.binary_analysis.uaf_cross_function import CrossFunctionUAFDetector
from modules.analysis.static.binary_analysis.uaf_risk_classifier import classify_use_risk, UAFRiskLevel
from modules.analysis.static.tools.compiler_aware_normalizer import CompilerAwareNormalizer

t0 = time.perf_counter(); results = []

# 1. Heap overflow: 6 tests
d = FilteredHeapOverflowDetector()
heap_tests = [
    (True,  "mov edi, 64|call malloc|mov rdi, rax|mov edx, 256|call memcpy"),
    (False, "mov edi, 14|call malloc|mov rdi, rax|mov edx, 15|call memcpy"),
    (False, "mov edi, 64|call malloc|mov rdi, rax|mov edx, 64|call memcpy"),
    (True,  "mov edi, 128|call malloc|mov rdi, rax|mov edx, 512|call memcpy"),
    (False, "mov edi, 100|call malloc|mov rdi, rax|cmp edx, 100|jb 0x500|mov edx, 200|call memcpy"),
    (True,  "mov edi, 64|call malloc|mov rbx, rax|mov edi, 256|call malloc|mov rdi, rax|mov edx, 300|call memcpy"),
]
ho = 0
for i, (exp, asm_str) in enumerate(heap_tests):
    asm = [(j, t.strip()) for j, t in enumerate(asm_str.split("|"))]
    r = d.detect({str(i): asm})
    ho += (any(f.verdict.value == "confirmed" for f in r) == exp)
results.append(("Heap Overflow", ho == 6))

# 2. Format string
fs = FormatStringDetector()
fs_r = fs.detect({"f": [(0,"mov rdi, [rsp]"),(1,"call read"),(2,"mov rdi, rax"),(3,"call printf")]})
results.append(("Format String", len(fs_r) > 0 and fs_r[0].verdict.value == "true_positive"))

# 3. Format spec analyzer
fsa = FormatSpecAnalyzer()
fsa_r = fsa.analyze("hello %s: %d")
results.append(("Fmt Spec", fsa_r.risk_level.value == "memory_read"))

# 4. Format size-aware
filt = FmtSizeAwareFilter()
rd = filt.analyze("printf", [(0x4000,"mov rdi, rax")], 0x4004)
rs = filt.analyze("snprintf", [(0x4000,"mov esi, 256"),(0x4002,"mov rdi, rax")], 0x4004)
results.append(("Fmt Size", rd.verdict == SizeAwareVerdict.DANGEROUS and rs.verdict == SizeAwareVerdict.SIZE_PROTECTED))

# 5. UAF detection
uaf = UAFDetector()
uaf_r = uaf.detect({"f": [(0,"call malloc"),(1,"mov [rbp-8], rax"),(2,"mov rdi, rax"),(3,"call free"),(4,"mov rax, [rbp-8]"),(5,"mov rdi, [rax]"),(6,"ret")]})
results.append(("UAF Detect", len(uaf_r) > 0 and uaf_r[0].verdict.value in ("confirmed","likely","possible")))
# 5b. Cross-function UAF
uaf_x = CrossFunctionUAFDetector()
uaf_xr = uaf_x.detect_cross_function(
    {"caller":[(0,"call malloc"),(1,"mov rdi, rax"),(2,"call callee"),(3,"mov byte [rdi], 0"),(4,"ret")],
     "callee":[(0,"push rbp"),(1,"call free"),(2,"pop rbp"),(3,"ret")]},
    {"caller":["callee"],"callee":[]})
results.append(("UAF Cross-Func", len(uaf_xr) > 0))

# 6. UAF risk classifier
ro = 0
for insn, exp in [("mov [rax], 0",UAFRiskLevel.CRITICAL),("call [rax]",UAFRiskLevel.CRITICAL),
    ("mov rbx, [rax]",UAFRiskLevel.MEDIUM),("cmp [rax], 0",UAFRiskLevel.LOW)]:
    ro += (classify_use_risk(insn)[0] == exp)
results.append(("UAF Risk", ro == 4))

# 7. Compiler normalizer
cn = CompilerAwareNormalizer()
cn_r = cn.normalize_function_calls([(0,"call __libc_malloc"),(1,"call __printf_chk")])
results.append(("Compiler Norm", "malloc" in cn_r[0][1] and "printf" in cn_r[1][1]))

elapsed = (time.perf_counter() - t0) * 1000
all_pass = all(r[1] for r in results)
for name, ok in results: print(f"  [{'OK' if ok else 'FAIL'}] {name}")
print(f"ALL: {'PASS' if all_pass else 'SOME FAILED'} ({elapsed:.1f}ms)")
