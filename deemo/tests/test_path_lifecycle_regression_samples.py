"""
路径条件对象生命周期回归测试 C 样本 — 路径条件对象生命周期分析.

样本分类:
  - MUTEX_SAFE (8):   UAF 对象身份图误报, 路径条件对象生命周期应过滤为SAFE
  - EARLY_RETURN (4): free后early return使use不可达
  - CONFIRMED (7):    真实UAF, 路径条件对象生命周期应保持CONFIRMED
  - NULLIFY/REASSIGN (2): 安全模式, 非UAF
"""

# MUTEX_SAFE — UAF 对象身份图误报, 路径条件对象生命周期应过滤为SAFE

MUTEX_01 = """
char *p = malloc(64);
if (error) {
    free(p);
}
if (!error) {
    *p = 1;
}
"""

MUTEX_02 = """
char *p = malloc(64);
if (error) {
    free(p);
} else {
    *p = 1;
}
"""

MUTEX_03 = """
char *p = malloc(64);
if (mode == 1) {
    free(p);
}
if (mode != 1) {
    *p = 1;
}
"""

MUTEX_04 = """
char *p = malloc(64);
if (flag) {
    free(p);
}
if (!flag) {
    p[0] = 42;
}
"""

MUTEX_05 = """
char *p = malloc(64);
int saved = active;
if (active) {
    free(p);
}
active = saved;
if (!active) {
    *p = 1;
}
"""

MUTEX_06 = """
char *p = malloc(64);
if (status) {
    free(p);
    return;
}
if (!status) {
    *p = 1;
}
"""

MUTEX_07 = """
char *p = malloc(64);
if (err_code) {
    free(p);
}
if (!err_code) {
    p->field = 0;
}
"""

MUTEX_08 = """
char *p = malloc(64);
if (enabled) {
    free(p);
}
if (!enabled) {
    memcpy(p, src, 32);
}
"""

# EARLY_RETURN — free后return/exit使use不可

EARLY_01 = """
char *p = malloc(64);
if (error) {
    free(p);
    return;
}
*p = 1;
"""

EARLY_02 = """
char *p = malloc(64);
if (error) {
    free(p);
    return -1;
}
p[0] = 42;
"""

EARLY_03 = """
char *p = malloc(64);
if (fatal) {
    free(p);
    exit(1);
}
*p = 1;
"""

EARLY_04 = """
char *p = malloc(64);
if (bad) {
    free(p);
    return;
}
if (good) {
    *p = 1;
}
"""

# CONFIRMED — 真实UAF, 路径条件对象生命周期应保持CONFIRMED

CONF_01 = """
char *p = malloc(64);
if (cond) {
    free(p);
    *p = 1;
}
"""

CONF_02 = """
char *p = malloc(64);
if (error) {
    free(p);
}
*p = 1;
"""

CONF_03 = """
char *p = malloc(64);
free(p);
*p = 1;
"""

CONF_04 = """
char *p = malloc(64);
if (a) {
    free(p);
}
if (b) {
    *p = 1;
}
"""

CONF_05 = """
char *p = malloc(64);
if (error) {
    free(p);
}
if (error) {
    *p = 1;
}
"""

CONF_06 = """
char *p = malloc(64);
char *q = p;
free(p);
*q = 42;
"""

CONF_07 = """
char *p = malloc(64);
if (cond) {
    free(p);
    return;
}
free(p);
*p = 1;
"""

# NULLIFY/REASSIGN — 安全模式, 非UAF

NULLIFY_01 = """
char *p = malloc(64);
if (error) {
    free(p);
    p = NULL;
}
*p = 1;
"""

REASSIGN_01 = """
char *p = malloc(64);
if (error) {
    free(p);
}
p = malloc(128);
*p = 1;
"""

# 样本注册

ALL_SAMPLES = {
    # 路径条件对象生命周期应过滤为SAFE (UAF 对象身份图会CONFIRMED的误报)
    'mutex_01': (MUTEX_01, 'SAFE'),
    'mutex_02': (MUTEX_02, 'SAFE'),
    'mutex_03': (MUTEX_03, 'SAFE'),
    'mutex_04': (MUTEX_04, 'SAFE'),
    'mutex_05': (MUTEX_05, 'SAFE'),
    'mutex_06': (MUTEX_06, 'SAFE'),
    'mutex_07': (MUTEX_07, 'SAFE'),
    'mutex_08': (MUTEX_08, 'SAFE'),
    'early_01': (EARLY_01, 'SAFE'),
    'early_02': (EARLY_02, 'SAFE'),
    'early_03': (EARLY_03, 'SAFE'),
    'early_04': (EARLY_04, 'SAFE'),
    # 安全模式
    'nullify_01': (NULLIFY_01, 'SAFE'),
    'reassign_01': (REASSIGN_01, 'SAFE'),
    # 路径条件对象生命周期应保持CONFIRMED (真实UAF)
    'conf_01': (CONF_01, 'CONFIRMED'),
    'conf_02': (CONF_02, 'CONFIRMED'),
    'conf_03': (CONF_03, 'CONFIRMED'),
    'conf_04': (CONF_04, 'CONFIRMED'),
    'conf_05': (CONF_05, 'CONFIRMED'),
    'conf_06': (CONF_06, 'CONFIRMED'),
    'conf_07': (CONF_07, 'CONFIRMED'),
}
