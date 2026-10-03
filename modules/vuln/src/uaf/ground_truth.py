"""DRIFT UAF检测评测数据集 — 带ground truth标签的UAF样本.

每个样本包含: 路径, 预期UAF数量, 预期DoubleFree数量, 分类.
用于计算DRIFT的precision/recall/F1分数.

创建: 2025-06-09
"""
import os

# 已知UAF样本及其ground truth
# 格式: (样本名, UAF数量, DoubleFree数量, 类别)
# 类别: simple (函数内UAF), cross_fn (跨函数UAF), conditional (条件路径UAF),
#       safe (无UAF), double_free (双重释放)
UAF_GROUND_TRUTH = {
    # exploit/tests/regression/build/gcc/O0/
    'cve_uaf_03.exe': (0, 0, 'safe'),         # callback BEFORE free(o) at O0 — no UAF at binary level
    'cve_uaf_04.exe': (1, 0, 'cross_fn'),     # 类似跨函数模式
    'cve_uaf_05.exe': (0, 0, 'safe'),          # UAF只在flag=1路径上, 但编译时flag=0
    'cve_uaf_06.exe': (1, 0, 'conditional'),   # 条件路径上的UAF
    'cve_uaf_07.exe': (1, 0, 'simple'),        # 函数内简单UAF
    'cve_uaf_08.exe': (1, 0, 'cross_fn'),     # 跨函数UAF
    'cve_uaf_09.exe': (1, 0, 'conditional'),   # maybe_free(p,1): free(p)后p->field=0 — 条件UAF
    'cve_uaf_10.exe': (1, 0, 'simple'),        # 函数内简单UAF
    'cve_uaf_11.exe': (1, 0, 'double_free'),   # 双重释放

    # uaf_test samples
    'uaf_test_01': (1, 0, 'simple'),
    'uaf_test_02': (1, 0, 'simple'),

    # uaf_extra samples
    'uaf_extra_01': (1, 0, 'conditional'),
    'uaf_extra_02': (1, 0, 'cross_fn'),
    'uaf_extra_03': (0, 0, 'safe'),
    'uaf_extra_04': (1, 0, 'double_free'),
    'uaf_extra_05': (1, 0, 'conditional'),
    'uaf_extra_06': (1, 0, 'cross_fn'),
    'uaf_extra_07': (2, 1, 'double_free'),
    'uaf_extra_08': (0, 0, 'safe'),
    'uaf_extra_09': (1, 0, 'simple'),

    # DRIFT Temporal Path Verifier 12-sample benchmark
    'sample_uaf_01_simple': (1, 0, 'simple'),
    'sample_uaf_02_reg_overwrite': (0, 0, 'safe_fp'),
    'sample_uaf_03_conditional': (1, 0, 'conditional'),
    'sample_uaf_04_alias': (1, 0, 'cross_fn'),
    'sample_uaf_05_multi_obj': (0, 0, 'safe_multi'),
    'sample_uaf_06_cross_fn': (1, 0, 'cross_fn'),
    'sample_uaf_07_double_free': (1, 0, 'double_free'),
    'sample_uaf_08_realloc': (1, 0, 'cross_fn'),
    'sample_uaf_09_safe_stack': (0, 0, 'safe_no_heap'),
    'sample_uaf_10_safe_no_free': (0, 0, 'safe_no_free'),
    'sample_uaf_11_struct_field': (1, 0, 'cross_fn'),
    'sample_uaf_12_loop': (1, 0, 'conditional'),
}

# 仅考虑存在的二进制文件
def get_available_samples(base_dirs: list) -> dict:
    """返回所有可用的样本及其ground truth."""
    available = {}
    for base in base_dirs:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            for f in files:
                if not f.endswith('.exe'):
                    continue
                # 从文件名提取样本名
                name = f.replace('.exe', '')
                if f in UAF_GROUND_TRUTH:
                    available[os.path.join(root, f)] = UAF_GROUND_TRUTH[f]
                elif name in UAF_GROUND_TRUTH:
                    available[os.path.join(root, f)] = UAF_GROUND_TRUTH[name]
    return available
