import json, os, sys
DEMO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
f = open(os.path.join(DEMO, '.temp/results_heap/heap_scan_with_llm.json'), 'r', encoding='utf-8')
data = json.load(f)
f.close()
for r in data['results'][:8]:
    llm = r.get('llm', {})
    resp = llm.get('response', {})
    content = ''
    if isinstance(resp, dict):
        content = resp.get('content', '') or resp.get('response', '') or str(resp)[:300]
    elif isinstance(resp, str):
        content = resp[:300]
    print('### {} (findings={})'.format(r['sample'], r['total_findings']))
    print('LLM status={}, elapsed={}s'.format(llm.get('status'), llm.get('elapsed_sec')))
    print('LLM head: {}'.format(content[:400]))
    print()
