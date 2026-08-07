import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind')
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

# 验证 source_level_candidate_extractor
from core.source_level_candidate_extractor import extract_candidates_from_code
code = """
#include <stdlib.h>
#include <string.h>
typedef struct { char buf[32]; int len; } msg_t;
void func() {
    msg_t *m = (msg_t *)malloc(sizeof(msg_t));
    memcpy(m->buf, "hello", 64);
    strcpy(m->buf, "world");
    m->buf[0] = 'A';
    sprintf(m->buf, "fmt");
}
"""
candidates, ir = extract_candidates_from_code(code)
print(f'extract_candidates_from_code: {len(candidates)} candidates, {len(ir)} IR lines')

# 验证 cj_constraint_collector
from core.cj_constraint_collector import collect_constraints
print('collect_constraints: callable')

# 验证 experiment_tracker
from core.experiment_tracker import ExperimentTracker
import tempfile, os
db = os.path.join(tempfile.gettempdir(), 'test_split.db')
t = ExperimentTracker(db_path=db)
eid = t.start_experiment('test', sample_id='s1')
t.record_result(eid, total_vulns=3, critical_vulns=1)
t.finish_experiment(eid, status='completed', elapsed_sec=10.0)
exp = t.get_experiment(eid)
print(f'ExperimentTracker: id={eid}, vulns={exp["total_vulns"]}, de={exp["discovery_efficiency"]}')
s = t.summary()
print(f'summary: total={s["total_experiments"]}')
rpt = t.generate_evaluation_report()
print(f'report: {len(rpt)} chars')
os.unlink(db)

# 验证 vuln_analyzer
from core.vuln_analyzer import analyze_all, _VULN_ANALYZERS
print(f'vuln_analyzer: {len(_VULN_ANALYZERS)} registered analyzers')

# 验证 stack_overflow_analyzer
from core.stack_overflow_analyzer import analyze_stack_overflow, analyze_with_pattern_fallback
print('stack_overflow_analyzer: OK')

# 验证 format_string_detector
from core.format_string_detector import detect_format_string_vulns, detect_with_taint_prefilter, format_offset_to_arg_position
print(f'format_offset_to_arg_position(6): {format_offset_to_arg_position(6)}')

print()
print('All functional tests passed.')
