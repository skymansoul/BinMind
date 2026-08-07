import sys, re
sys.stdout.reconfigure(encoding='utf-8')

# 修复规则: 损坏字符 —(em-dash) 在特定上下文中应恢复为原始字符
# 模式1: _check_case("xxx—, """  →  _check_case("xxx值", """
# 模式2: _check_case("xxx—unsafe  →  _check_case("xxx unsafe
# 模式3: _check_case("xxx—受限  →  _check_case("xxx, 受限  
# 模式4: 注释中的 — 应替换为合适的标点

for fname in ['test_pcfc_regression.py', 'test_fcpv_regression.py']:
    with open(fname, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    fixed = 0
    for i, line in enumerate(lines):
        if '—' not in line:
            continue
        
        # _check_case调用中的 — 修复
        # 模式: "_check_case("xxx—, """ → 需要在—位置加引号
        m = re.match(r'^(\s*_check_case\(".*?)—,\s*"""', line)
        if m:
            lines[i] = line.replace('—,', '",')
            fixed += 1
            continue
        
        # 模式: _check_case("1.常量格式—, """
        m = re.match(r'^(\s*_check_case\(".*?)—,\s*"""', line)
        if m:
            lines[i] = line.replace('—,', '",')
            fixed += 1
            continue
            
        # 通用: _check_case中的 —后跟,和"""
        if '_check_case(' in line and '—,' in line and '"""' in line:
            lines[i] = line.replace('—,', '",')
            fixed += 1
            continue
        
        # _check_case中的 —后跟, (不跟""")
        if '_check_case(' in line and '—,' in line:
            lines[i] = line.replace('—,', '",')
            fixed += 1
            continue
        
        # 其他 — 替换为逗号或空格
        if '_check_case(' in line:
            lines[i] = line.replace('—', ' ')
            fixed += 1
            continue
        
        # 注释行中的 — 替换为冒号
        stripped = line.lstrip()
        if stripped.startswith('#'):
            lines[i] = line.replace('—', ':')
            fixed += 1
            continue
    
    with open(fname, 'w', encoding='utf-8', newline='') as f:
        f.writelines(lines)
    
    # 验证
    text = ''.join(lines)
    try:
        compile(text, fname, 'exec')
        print(f'{fname}: OK ({fixed} fixes)')
    except SyntaxError as e:
        print(f'{fname}: SYNTAX ERROR at line {e.lineno}: {e.msg}')
        for j in range(max(0, e.lineno-3), min(len(lines), e.lineno+2)):
            print(f'  {j+1}: {lines[j].rstrip()[:80]}')
