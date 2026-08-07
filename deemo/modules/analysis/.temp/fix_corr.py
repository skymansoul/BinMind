import sys
sys.stdout.reconfigure(encoding='utf-8')

fpath = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\static\symbolic_correlator.py'
with open(fpath, 'r', encoding='utf-8') as f:
    content = f.read()

# 在 _check_pair 方法中, 所有 CorrelationResult(...) 调用缺少 alloc_addr, write_addr
# 找到 _check_pair 方法体, 在每个 return CorrelationResult(...) 的参数列表末尾加 alloc_addr, write_addr
import re

# 匹配 _check_pair 中的 CorrelationResult 调用
# 策略: 在 _check_pair 方法范围内的每个 CorrelationResult(...) 最后一行加 alloc_addr, write_addr
lines = content.split('\n')
in_check_pair = False
modified = 0
new_lines = []

for i, line in enumerate(lines):
    if 'def _check_pair' in line:
        in_check_pair = True
    elif in_check_pair and line and not line[0].isspace() and 'def ' in line:
        in_check_pair = False
    
    if in_check_pair and 'alloc_expr, write_expr)' in line and 'alloc_addr, write_addr' not in line:
        line = line.replace('alloc_expr, write_expr)', 'alloc_expr, write_expr, alloc_addr, write_addr)')
        modified += 1
    
    new_lines.append(line)

with open(fpath, 'w', encoding='utf-8', newline='') as f:
    f.write('\n'.join(new_lines))

print(f'Modified {modified} CorrelationResult calls')
