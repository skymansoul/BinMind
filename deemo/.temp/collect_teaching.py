import json, os, glob

DEMO = r'C:\Users\Administrator\Desktop\BinMind\deemo'
teaching_dir = os.path.join(DEMO, '.temp/results_teaching')

# 收集教学样本扫描结果
json_files = sorted(glob.glob(os.path.join(teaching_dir, '*.json')))
# 去重，每个样本取最新
latest = {}
for jf in json_files:
    fname = os.path.basename(jf)
    sample_id = fname.split('_2026')[0]
    if sample_id not in latest or jf > latest[sample_id]:
        latest[sample_id] = jf

print('=== 教学样本扫描结果 ===')
for sample_id, jf in sorted(latest.items()):
    f = open(jf, 'r', encoding='utf-8')
    data = json.load(f)
    f.close()

    findings = data.get('findings', [])
    total = len(findings)

    # 统计严重性分布
    sev_counts = {}
    for find in findings:
        sev = find.get('severity', 'unknown')
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # 统计来源（rule vs analysis/llm）
    source_counts = {}
    for find in findings:
        src = find.get('_source', 'unknown')
        source_counts[src] = source_counts.get(src, 0) + 1

    # 统计 CWE
    cwe_list = set()
    for find in findings:
        cwe = find.get('cwe', '') or find.get('cwe_id', '')
        if cwe:
            cwe_list.add(cwe)

    # 统计漏洞类型
    type_list = set()
    for find in findings:
        vtype = find.get('vuln_type', '') or find.get('type', '')
        if vtype:
            type_list.add(vtype)

    print('{} | total={} | sev={} | src={} | CWE={} | types={}'.format(
        sample_id, total,
        dict(sev_counts),
        dict(source_counts),
        sorted(cwe_list),
        sorted(type_list)
    ))
