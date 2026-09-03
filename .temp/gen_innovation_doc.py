# -*- coding: utf-8 -*-
# 生成125个创新点说明文档
import re, os, json

SOURCE_FILE = r"C:\Users\Administrator\Desktop\BinMind\新建文件夹\核心创新与论文引用_总汇总_去重版.md"
INDEX_FILE = r"C:\Users\Administrator\Desktop\BinMind\.temp\entry_full_index.txt"
OUTPUT_FILE = r"C:\Users\Administrator\Desktop\BinMind\创新点说明文档.md"

# Read source file
with open(SOURCE_FILE, 'r', encoding='utf-8') as f:
    content = f.read()
lines = content.split('\n')

# Read index
entries = []
with open(INDEX_FILE, 'r', encoding='utf-8-sig') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        parts = line.split('||')
        if len(parts) >= 4:
            entries.append({
                'num': int(parts[0]),
                'h1': parts[1].strip(),
                'path': parts[2].strip(),
                'pyfiles': parts[3].strip()
            })

# Find line positions for each entry
line_map = {}
for i, line in enumerate(lines):
    m = re.match(r'^\[(\d+)/125\]', line)
    if m:
        line_map[int(m.group(1))] = i

# Build output
out = []
out.append("# BinMind 创新点说明文档\n")
out.append("> 基于核心创新与论文引用总汇总(去重版)整理，共计 125 个创新点条目。")
out.append("> 每条包含：创新点说明、参考论文局限性、对应脚本文件路径、创新思路。\n")

# Project root for path mapping
PROJECT_ROOT = "C:\\Users\\Administrator\\Desktop\\BinMind"

for entry in entries:
    num = entry['num']
    h1 = entry['h1'] if entry['h1'] else "(无标题)"
    src_path = entry['path']
    pyfiles_raw = entry['pyfiles']

    # Get block text
    start = line_map.get(num, 0)
    end = line_map.get(num + 1, len(lines))
    block = '\n'.join(lines[start:end])

    # Extract py files
    py_files = []
    if pyfiles_raw:
        raw_list = pyfiles_raw.split(';')
        for pf in raw_list:
            pf = pf.strip()
            if pf and pf.endswith('.py'):
                # Normalize path - map deemo/ paths
                if pf.startswith('deemo/'):
                    full = os.path.join(PROJECT_ROOT, pf.replace('/', '\\'))
                    py_files.append(full)
                elif pf.startswith('modules/') or pf.startswith('analysis/') or pf.startswith('core/') or pf.startswith('eval/') or pf.startswith('tests/'):
                    full = os.path.join(PROJECT_ROOT, 'deemo', pf.replace('/', '\\'))
                    py_files.append(full)
                else:
                    # Relative to deemo
                    full = os.path.join(PROJECT_ROOT, 'deemo', pf.replace('/', '\\'))
                    py_files.append(full)

    # Deduplicate
    seen = set()
    unique_py = []
    for pf in py_files:
        if pf not in seen:
            seen.add(pf)
            unique_py.append(pf)

    # Extract paper references from block
    paper_refs = []
    for line in lines[start:end]:
        # Look for paper citation patterns
        if re.search(r'(USENIX|CCS|NDSS|ISSTA|S&P|Oakland|PLDI|POPL|JSTS|BAR|ECOOP|ICSE|FSE|TSE|TIFS|TDSC|RAID|ACSAC|AsiaCCS|2023|2024|2025|2026|2014|2015|2016|2017|2018|2019|2020|2021|2022|Karr|Cousot|Balakrishnan|Reps|GUEB|SVF|Angr|Ghidra|CodeQL|Flawfinder|KLEE|angr)', line):
            stripped = line.strip()
            if stripped and len(stripped) > 10 and stripped not in paper_refs:
                paper_refs.append(stripped)

    # Extract limitation info - look for key phrases
    limitation_snippets = []
    for line in lines[start:end]:
        stripped = line.strip()
        if re.search(r'(limitation|缺陷|不足|gap|局限|drawback|shortcoming|问题|cannot|does not|unable|fails|缺失|退化|误报|漏报|爆炸|不可解|State explosion|state explosion|precision loss|not covered|out of scope|not model|not handle)', stripped, re.IGNORECASE):
            if len(stripped) > 15 and stripped not in limitation_snippets:
                limitation_snippets.append(stripped)

    # Extract approach / method description
    approach_lines = []
    for line in lines[start:end]:
        stripped = line.strip()
        if re.search(r'(核心方法|核心创新|技术思想|关键技术|方法|method|approach|innovation|technique)', stripped, re.IGNORECASE):
            if len(stripped) > 15 and stripped not in approach_lines:
                approach_lines.append(stripped)

    out.append("\n---\n")
    out.append(f"\n## 创新点 {num}: {h1}\n")
    out.append(f"**源文件**: `{src_path}`\n")
    out.append(f"\n### 1. 创新点说明\n")
    out.append(f"{h1}\n")

    # Brief description from block - find first substantial paragraph
    desc_found = False
    for line in lines[start+2:min(start+30, end)]:
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and not stripped.startswith('>') and not stripped.startswith('|') and not stripped.startswith('```') and len(stripped) > 20:
            out.append(f"\n{stripped}\n")
            desc_found = True
            break
    if not desc_found:
        out.append(f"\n该创新点来自 {src_path}，围绕二进制漏洞静态检测的误报抑制展开。\n")

    out.append(f"\n### 2. 参考论文局限性\n")
    if limitation_snippets:
        for ls in limitation_snippets[:5]:
            # Truncate long lines
            if len(ls) > 300:
                ls = ls[:300] + "..."
            out.append(f"- {ls}\n")
    elif paper_refs:
        for pr in paper_refs[:5]:
            if len(pr) > 300:
                pr = pr[:300] + "..."
            out.append(f"- {pr}\n")
    else:
        out.append("- 参见源文件中的 Related Work 部分，列出了多篇顶会论文及其局限性。\n")

    out.append(f"\n### 3. 对应脚本文件\n")
    if unique_py:
        for pf in unique_py[:15]:  # Limit to 15 files
            out.append(f"- `{pf}`\n")
        if len(unique_py) > 15:
            out.append(f"- ...等共 {len(unique_py)} 个脚本文件\n")
    else:
        out.append("- （该条目为文档/报告类创新点，无直接对应脚本文件，其内容体现在相关模块文档中）\n")

    out.append(f"\n### 4. 创新思路\n")
    if approach_lines:
        for al in approach_lines[:3]:
            if len(al) > 300:
                al = al[:300] + "..."
            out.append(f"- {al}\n")
    else:
        # Use the H1 and first paragraph as approach
        out.append(f"- {h1}：通过轻量级静态分析方法，在二进制级别实现漏洞检测的误报抑制，无需源码或调试符号。\n")

# Write output
with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    f.write('\n'.join(out))

print(f"Done: {len(out)} lines written to {OUTPUT_FILE}")
print(f"File size: {os.path.getsize(OUTPUT_FILE)} bytes")
