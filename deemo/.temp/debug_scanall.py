#!/usr/bin/env python3
"""调试scan_all的完整链路."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, "modules/vuln/tests/regression_heap")

from scan_scheduler import scan_all

results = scan_all()
print(f"Total results: {len(results)}")
for r in results[:5]:
    print(f"  {r.get('sample_id')}: findings={len(r.get('findings',[]))} "
          f"err={r.get('error','')[:80]} time={r.get('time_ms',0)}")
