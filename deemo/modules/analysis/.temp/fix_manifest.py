import sys, json
from pathlib import Path

# SAWCE样本的正确预期行为:
# - same_source: binary包含_vuln(安全) + _diff(溢出) → expected_vuln=True
# - derived_boundary: 只有_vuln(sz+1写入, padding内安全) → expected_vuln=False
# - loop_accumulate: 包含_vuln(5*64=320>256,溢出) + _safe(3*64=192,安全) → expected_vuln=True
# - nested_call: 只有_vuln(get_size()同源,安全) → expected_vuln=False
# - arithmetic: 只有_vuln(count*4同源,安全) → expected_vuln=False

mp = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_manifest.json")
m = json.loads(mp.read_text(encoding="utf-8-sig"))

for e in m:
    name = e["name"]
    if name == "sawce_same_source":
        e["expected_vulnerable"] = True
        e["challenge"] = "SAWCE must filter _vuln (same_source safe) but detect _diff (overflow: 128>64)"
    elif name == "sawce_loop_accumulate":
        e["expected_vulnerable"] = True
        e["challenge"] = "Stage 10 must detect loop in _vuln (5*64=320>256) while _safe (3*64=192) is safe"
    elif name == "sawce_derived_boundary":
        e["expected_vulnerable"] = False
    elif name == "sawce_nested_call":
        e["expected_vulnerable"] = False
    elif name == "sawce_arithmetic":
        e["expected_vulnerable"] = False

mp.write_text(json.dumps(m, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"Updated {len(m)} manifest entries")
for e in m:
    if e["opt"] == "O0":
        print(f"  {e['name']}: expected_vuln={e['expected_vulnerable']}")
