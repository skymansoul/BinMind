import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_interproc_free import InterprocFreeAnalyzer
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\cross_function_vuln_O2.exe'
insns = _disassemble(binary)
ia = InterprocFreeAnalyzer(use_win64_abi=True)
# 从 pre_analyze 获取 func_ranges
from modules.analysis.static.uaf_pre_analyzer import UAFPreAnalyzer as PreAnalyzer
pa = PreAnalyzer()
pa.analyze_from_instructions(insns)
ia.build_summaries(insns, pa.user_func_ranges)

summary = ia._summaries.get("cross_free")
if summary:
    print(f"cross_free: freed_params={summary.freed_params} has_direct_free={summary.has_direct_free} calls_free_like={summary.calls_free_like}")
else:
    print("cross_free: NOT IN SUMMARIES")

# 打印 cross_free 的指令
cross_free_insns = [i for i in insns if 0x140001760 <= i.get("address",0) < 0x140001770]
print("\ncross_free instructions:")
for ins in cross_free_insns:
    print(f"  {hex(ins.get('address',0))}: {ins.get('mnemonic','')} {ins.get('operands',[])}")
