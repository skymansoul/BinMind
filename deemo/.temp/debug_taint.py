"""调试 sample01 taint收集."""
import sys
sys.path.insert(0, '.')

from core.fcpv_constraint_collector import FcpvConstraintCollector

src = open('modules/vuln/detection/src/format/fmt_samples/sample01_direct_fmt_vuln/main.c',
           encoding='utf-8', errors='replace').read()
c = FcpvConstraintCollector()
cands = c.collect(src)
print('Tainted:', c.tainted_set)
print('Sources:', c._taint_sources)
sink = cands[0].sink
print(f'fmt_arg={sink.fmt_arg!r} var={sink.var!r}')
print(f'var "{sink.var}" in tainted? {sink.var in c.tainted_set}')
taints = c._collect_taints(sink.var, sink.line)
print(f'Taints for var={sink.var!r}: {taints}')
for sl, src_name, tv in c._taint_sources:
    print(f'  source: sl={sl} src={src_name} tv={tv!r} tv==var? {tv==sink.var}')
