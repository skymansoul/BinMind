#!/usr/bin/env python3
"""
智能拆分: 对于单class超长文件, 按方法边界拆分class到part1/part2.
策略: 如果part1/part2拆分后仍超标, 说明有个巨大的class, 需要按方法边界拆分.
"""
import os, re

TESTS_DIR = r"C:\Users\Administrator\Desktop\BinMind\deemo\tests"
MAX_LINES = 300


def find_method_starts(lines):
    """找所有class内方法的行号 (4空格缩进的def)."""
    methods = []
    for i, line in enumerate(lines):
        if re.match(r'^    def\s+\w+', line):
            methods.append(i)
    return methods


def split_at_method_boundary(filepath):
    """在方法边界处拆分, 保证每个part <= MAX_LINES."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    total = len(lines)
    if total <= MAX_LINES:
        return True

    basename = os.path.basename(filepath)
    name_base = basename[:-3]
    
    # 找所有方法边界
    method_starts = find_method_starts(lines)
    if not method_starts:
        # 没有方法, 按行号中点拆分
        mid = total // 2
        part1 = lines[:mid]
        part2_header = []
        # 收集imports
        for line in lines:
            s = line.strip()
            if (s.startswith('import ') or s.startswith('from ') or 
                s.startswith('#') or s.startswith('#!') or 
                'sys.path' in s or '_MOD_DEBUG' in s or
                not s or s.startswith('"""')):
                part2_header.append(line)
            else:
                break
        part2 = part2_header + ['\n'] + lines[mid:]
    else:
        # 找最佳方法拆分点: 使part1和part2都尽量不超过MAX_LINES
        best_split = None
        for i, ms in enumerate(method_starts):
            part1_len = ms
            part2_len = total - ms + 30  # 30 = 大约header行数
            if part1_len <= MAX_LINES and part2_len <= MAX_LINES:
                best_split = ms
                break  # 第一个满足条件的
        
        if best_split is None:
            # 没有拆分点能让两部分都 <=300, 取最接近的
            best_split = method_starts[len(method_starts)//2]
        
        part1 = lines[:best_split]
        
        # 构建part2的header
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

        part2 = lines[:header_end] + ['\n'] + lines[best_split:]

    part1_path = os.path.join(TESTS_DIR, f"{name_base}_part1.py")
    part2_path = os.path.join(TESTS_DIR, f"{name_base}_part2.py")

    with open(part1_path, 'w', encoding='utf-8') as f:
        f.writelines(part1)
    with open(part2_path, 'w', encoding='utf-8') as f:
        f.writelines(part2)

    p1l = len(part1)
    p2l = len(part2)
    ok = p1l <= MAX_LINES and p2l <= MAX_LINES
    
    if ok:
        os.remove(filepath)
        print(f"  [OK] {basename}: {total} -> p1={p1l} p2={p2l}")
    else:
        # 删原文件, 保留parts (下一轮会继续拆分)
        os.remove(filepath)
        print(f"  [SPLIT] {basename}: {total} -> p1={p1l} p2={p2l}")
    
    return ok


def main():
    for round_num in range(10):
        over = []
        for f in sorted(os.listdir(TESTS_DIR)):
            if not f.endswith('.py') or '_samples' in f or '_cases' in f:
                continue
            fp = os.path.join(TESTS_DIR, f)
            with open(fp, 'r', encoding='utf-8', errors='replace') as fh:
                n = len(fh.readlines())
            if n > MAX_LINES:
                over.append((f, n))

        if not over:
            print(f"Round {round_num}: All files <= {MAX_LINES}")
            break

        print(f"Round {round_num}: {len(over)} files over limit")
        for f, n in over:
            print(f"  {f}: {n}")

        for f, n in over:
            fp = os.path.join(TESTS_DIR, f)
            split_at_method_boundary(fp)

    # Final check
    still = []
    for f in sorted(os.listdir(TESTS_DIR)):
        if not f.endswith('.py'):
            continue
        fp = os.path.join(TESTS_DIR, f)
        with open(fp, 'r', encoding='utf-8', errors='replace') as fh:
            n = len(fh.readlines())
        if n > MAX_LINES:
            still.append((f, n))

    if still:
        print(f"\nStill over limit ({len(still)}):")
        for f, n in still:
            print(f"  {f}: {n}")
    else:
        print(f"\nAll files <= {MAX_LINES} lines!")


if __name__ == '__main__':
    main()
