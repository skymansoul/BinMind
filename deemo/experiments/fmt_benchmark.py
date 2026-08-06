import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.taint_tracker import track_taint_intraprocedural, filter_by_taint

FMT_CASES = [
    ("FMT-01","char *m=recv(0,b,256,0);printf(m);",True),
    ("FMT-02","char *u=getenv('USER');fprintf(f,u);",True),
    ("FMT-03","char *d=read(0,buf,128);sprintf(out,d);",True),
    ("SAFE-01","printf('hello world');",False),
    ("SAFE-02","char *m='static string';printf(m);",False),
    ("SAFE-03","snprintf(buf,64,'format %s',user);",False),
]
tp_hits = fp_filtered = 0
for name, code, is_tp in FMT_CASES:
    f = [{'type':'format_string','description':code,'format_arg':''}]
    filtered = filter_by_taint(f, code, 'test')
    verified = any(x.get('taint_verified') for x in filtered)
    if is_tp: tp_hits += (1 if verified else 0)
    else: fp_filtered += (1 if not verified else 0)
summary = {
    'total': len(FMT_CASES), 'tp_samples': 3, 'fp_samples': 3,
    'fmt_detection_rate': round(tp_hits/3*100,1),
    'fp_filtered': fp_filtered,
    'fp_filter_rate': round(fp_filtered/3*100,1),
}
os.makedirs('experiments/results', exist_ok=True)
json.dump(summary, open('experiments/results/fmt_benchmark.json','w'), indent=2)
print(f"FMT: detection={summary['fmt_detection_rate']}% FP_filtered={summary['fp_filter_rate']}%")
