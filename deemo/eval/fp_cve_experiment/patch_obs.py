"""补丁: cve_2023_3576 增加可观测读取, 防止O2死代码消除."""
p = r'C:\Users\Administrator\Desktop\BinMind\deemo\eval\fp_cve_experiment\corpus\cve_2023_3576_openssl\vuln.c'
src = open(p, encoding='utf-8').read()
if 'printf' not in src:
    src = src.replace('#include <stdlib.h>',
                      '#include <stdlib.h>\n#include <stdio.h>')
    src = src.replace('    parse_varlen(der, 16, out, 8);\n    free(out);',
                      '    parse_varlen(der, 16, out, 8);\n'
                      '    printf("%d\\n", out[0]);\n    free(out);')
    open(p, 'w', encoding='utf-8').write(src)
    print('patched')
else:
    print('already')
