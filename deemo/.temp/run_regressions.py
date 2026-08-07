import sys
sys.path.insert(0, '.')
results_summary = []

# BVF
try:
    from tests.test_bvf_regression import run_all
    r = run_all()
    p = sum(1 for x in r if x['passed'])
    results_summary.append(f'BVF: {p}/{len(r)} PASS')
except Exception as e:
    results_summary.append(f'BVF: ERROR - {e}')

# CJ
try:
    from tests.test_cj_regression import run_all
    r = run_all()
    p = sum(1 for x in r if x['passed'])
    results_summary.append(f'CJ: {p}/{len(r)} PASS')
except Exception as e:
    results_summary.append(f'CJ: ERROR - {e}')

# FCPV
try:
    from tests.test_fcpv_regression import run_all
    r = run_all()
    p = sum(1 for x in r if x['passed'])
    results_summary.append(f'FCPV: {p}/{len(r)} PASS')
except Exception as e:
    results_summary.append(f'FCPV: ERROR - {e}')

# PC-BVF
try:
    from tests.test_pcbvf_regression import run_all
    r = run_all()
    p = sum(1 for x in r if x['passed'])
    results_summary.append(f'PC-BVF: {p}/{len(r)} PASS')
except Exception as e:
    results_summary.append(f'PC-BVF: ERROR - {e}')

# LSP
try:
    from tests.test_lsp_regression import run_all
    r = run_all()
    p = sum(1 for x in r if x['passed'])
    results_summary.append(f'LSP: {p}/{len(r)} PASS')
except Exception as e:
    results_summary.append(f'LSP: ERROR - {e}')

for s in results_summary:
    print(s)
