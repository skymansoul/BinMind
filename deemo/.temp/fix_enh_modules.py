"""修复 pipeline_enh_*.py 的拼写错误和缩进"""
import re

BASE = r"C:\Users\Administrator\Desktop\BinMind\deemo\core"

for i in range(1, 9):
    path = f"{BASE}\\pipeline_enh_{i}.py"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # 修复 ddef -> def
    content = content.replace("ddef ", "def ")
    
    # 修复缩进: 块内行当前有8空格，应改为4空格 (因为已经在函数体函数内)
    # 逐行处理
    lines = content.split('\n')
    new_lines = []
    in_func_body = False
    for line in lines:
        if line.startswith("def apply_enhancements_"):
            in_func_body = True
            new_lines.append(line)
            continue
        if in_func_body:
            # 如果行以8空格开头，删除4个
            if line.startswith("        "):
                new_lines.append(line[4:])
            elif line.strip() == '':
                new_lines.append('')
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    
    with open(path, "w", encoding="utf-8") as f:
        f.write('\n'.join(new_lines))
    
    line_count = len(new_lines)
    print(f"  pipeline_enh_{i}.py: {line_count} lines - fixed")

print("All modules fixed.")
