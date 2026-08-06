# 结果解析模块 — 汇总扫描结果，计算检出率/误报率
import json, os, csv

def parse_results(scan_output_json):
    with open(scan_output_json) as f:
        data = json.load(f)
    summary = {'total_binaries': 0, 'total_findings': 0,
               'by_type': {}, 'errors': 0, 'avg_time': 0.0}
    times = []
    for k, v in data.items():
        summary['total_binaries'] += 1
        findings = v.get('findings', []) if isinstance(v, dict) else []
        summary['total_findings'] += len(findings)
        for f_r in findings:
            t = f_r.get('type', 'unknown') if isinstance(f_r, dict) else 'unknown'
            summary['by_type'][t] = summary['by_type'].get(t, 0) + 1
        if v.get('error'):
            summary['errors'] += 1
        t = v.get('time_s', 0)
        if t > 0: times.append(t)
    if times: summary['avg_time'] = sum(times) / len(times)
    return summary

def generate_report(summary, cve_ground_truth, output_path):
    total = summary['total_binaries']
    true_positives = 0
    false_positives = summary['total_findings']
    for cve_dir, expected_type in cve_ground_truth.items():
        if expected_type in summary.get('by_type', {}):
            true_positives += 1
    detection_rate = true_positives / max(total, 1)
    fp_rate = (false_positives - true_positives) / max(total, 1)

    with open(output_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['Metric', 'Value'])
        w.writerow(['Total Binaries', total])
        w.writerow(['Detection Rate', f'{detection_rate:.1%}'])
        w.writerow(['False Positive Rate', f'{fp_rate:.1f}'])
        w.writerow(['Avg Scan Time (s)', f'{summary["avg_time"]:.1f}'])
        w.writerow(['Types Found', str(summary['by_type'])])
    return detection_rate, fp_rate

if __name__ == '__main__':
    import sys
    jf = sys.argv[1] if len(sys.argv) > 1 else '/tmp/deemo_results.json'
    s = parse_results(jf)
    print(json.dumps(s, indent=2))
