#!/usr/bin/env python3
"""批量拆分tests目录下超过300行的Python文件 — 按class/函数边界拆分."""
import os, re, sys

TESTS_DIR = r"C:\Users\Administrator\Desktop\BinMind\deemo\tests"
MAX_LINES = 300


def split_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    total = len(lines)
    if total <= MAX_LINES:
        return False

    basename = os.path.basename(filepath)
    name_base = basename[:-3]

    # 找所有顶层class和def的行号
    block_starts = []
    for i, line in enumerate(lines):
        s = line.rstrip()
        if re.match(r'^class\s+\w+', s) or re.match(r'^def\s+\w+', s):
            block_starts.append(i)

    if not block_starts:
        # 无class/def, 按行号中点拆
        split_pt = total // 2
        part1 = lines[:split_pt]
        part2 = lines[:30] + ['\n'] + lines[split_pt:]  # 前30行是imports
    else:
        # 找到接近中点的分割位置
        target = total * 0.55
        best = block_starts[0]
        for bs in block_starts:
            if bs > target:
                break
            best = bs

        if best == block_starts[0] and len(block_starts) > 1:
            best = block_starts[len(block_starts)//2]

        part1 = lines[:best]

        # part2: 复制头部imports + 从best开始
        # 提取imports (到第一个class/def或空行后非import行)
        header_end = 0
        in_docstring = False
        in_import_paren = False
        for i, line in enumerate(lines):
            s = line.strip()
            if i == 0 and '"""' in s:
                if s.count('"""') >= 2:
                    header_end = i + 1
                    continue
                in_docstring = True
                continue
            if in_docstring:
                header_end = i + 1
                if '"""' in s:
                    in_docstring = False
                continue
            if not s or s.startswith('#') or s.startswith('#!') or s.startswith('# -*-'):
                header_end = i + 1
                continue
            if s.startswith('from __future__') or s.startswith('import ') or s.startswith('from '):
                header_end = i + 1
                if '(' in s and ')' not in s:
                    in_import_paren = True
                continue
            if in_import_paren:
                header_end = i + 1
                if ')' in s:
                    in_import_paren = False
                continue
            if re.match(r'^[A-Za-z_]\w*\s*=', s) or 'sys.path' in s or '_MOD_DEBUG' in s:
                header_end = i + 1
                continue
            break

        part2 = lines[:header_end] + ['\n'] + lines[best:]

    # 写入文件
    part1_path = filepath[:-3] + '_part1.py'
    part2_path = filepath[:-3] + '_part2.py'

    with open(part1_path, 'w', encoding='utf-8') as f:
        f.writelines(part1)
    with open(part2_path, 'w', encoding='utf-8') as f:
        f.writelines(part2)

    p1l = len(part1)
    p2l = len(part2)
    print(f"  {basename}: {total} -> part1={p1l} part2={p2l}")

    if p1l <= MAX_LINES and p2l <= MAX_LINES:
        os.remove(filepath)
        print(f"    [OK]")
        return True
    else:
        # 还超标, 删除parts并标记需要再次拆分
        if p1l > MAX_LINES:
            print(f"    part1 still over ({p1l})")
        if p2l > MAX_LINES:
            print(f"    part2 still over ({p2l})")
        # 保留part文件, 删原文件 (后续会再次拆分)
        os.remove(filepath)
        return False


def main():
    # 多轮拆分直到所有文件都 <=300
    for round_num in range(5):
        over_limit = []
        for f in sorted(os.listdir(TESTS_DIR)):
            if not f.endswith('.py'):
                continue
            if '_samples' in f or '_cases' in f:
                continue
            fp = os.path.join(TESTS_DIR, f)
            with open(fp, 'r', encoding='utf-8', errors='replace') as fh:
                n = len(fh.readlines())
            if n > MAX_LINES:
                over_limit.append((f, n))

        if not over_limit:
            print(f"Round {round_num}: All files <= {MAX_LINES} lines")
            break

        print(f"Round {round_num}: {len(over_limit)} files over limit")
        for f, n in over_limit:
            print(f"  {f}: {n}")

        for f, n in over_limit:
            fp = os.path.join(TESTS_DIR, f)
            split_file(fp)

    # Final check
    still_over = []
    for f in sorted(os.listdir(TESTS_DIR)):
        if not f.endswith('.py'):
            continue
        fp = os.path.join(TESTS_DIR, f)
        with open(fp, 'r', encoding='utf-8', errors='replace') as fh:
            n = len(fh.readlines())
        if n > MAX_LINES:
            still_over.append((f, n))

    if still_over:
        print(f"\nStill over limit ({len(still_over)}):")
        for f, n in still_over:
            print(f"  {f}: {n}")
    else:
        print(f"\nAll files now <= {MAX_LINES} lines!")


if __name__ == '__main__':
    main()
