#!/usr/bin/env python3
"""修复 SYSCALL_MAP_X64 为 name -> number 格式"""
import re

with open(r'modules\sandbox_policy_gen.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 找到模块级 SYSCALL_MAP_X64（不在类内的）
# 第一次出现就是模块级
lines = content.split('\n')
start_idx = None
end_idx = None
brace_count = 0
for i, line in enumerate(lines):
    if start_idx is None:
        if re.match(r'^SYSCALL_MAP_X64 = \{', line):
            start_idx = i
            brace_count = 1
            continue
    else:
        brace_count += line.count('{')
        brace_count -= line.count('}')
        if brace_count == 0:
            end_idx = i
            break

if start_idx is None:
    print('未找到模块级 SYSCALL_MAP_X64')
    exit(1)

print(f'SYSCALL_MAP_X64 在第 {start_idx+1} 到 {end_idx+1} 行')

# 解析键值对
pairs = []
for i in range(start_idx + 1, end_idx):
    line = lines[i].strip().rstrip(',')
    if not line:
        continue
    # 格式: 数字: 'name'
    m = re.match(r"(\d+):\s*'(\w+)'", line)
    if m:
        num = int(m.group(1))
        name = m.group(2)
        pairs.append((num, name))

print(f'共 {len(pairs)} 对')

# 反转
reversed_pairs = [(name, num) for num, name in pairs]

# 重新构造
new_lines = []
for i in range(0, len(reversed_pairs), 4):
    chunk = reversed_pairs[i:i+4]
    line = ', '.join(f"'{n}': {v}" for n, v in chunk) + ','
    new_lines.append('    ' + line)

new_content = 'SYSCALL_MAP_X64 = {\n' + '\n'.join(new_lines) + '\n}'

# 替换
new_lines_all = lines[:start_idx] + new_content.split('\n') + lines[end_idx+1:]
with open(r'modules\sandbox_policy_gen.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(new_lines_all))

print('已反转 SYSCALL_MAP_X64')
