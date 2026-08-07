import json

with open(r'C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow\ground_truth.json', encoding='utf-8') as f:
    gt = json.load(f)

s = gt['samples']
vuln = sum(1 for v in s.values() if v['expected_vuln'])
safe = sum(1 for v in s.values() if not v['expected_vuln'])
print(f'Total: {len(s)}, Vuln: {vuln}, Safe: {safe}')
summary = gt['summary']
print(f'Summary: total={summary["total"]}, vuln={summary["vulnerable"]}, safe={summary["safe"]}')
print('Safe samples:', [k for k, v in s.items() if not v['expected_vuln']])
print('Vuln samples:', [k for k, v in s.items() if v['expected_vuln']])
