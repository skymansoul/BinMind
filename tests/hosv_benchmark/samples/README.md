# HOSV-Ext 堆溢出专项样本集

18 个针对堆溢出检测的专项样本 (12 VULN + 6 SAFE), 覆盖五个真实 CVE 写模式.
每个样本独立目录, 含 `vuln.c` / `Makefile` / `README.md` / `truth.json`.

## 样本清单

| # | 样本 | CVE | 模式 | 期望 |
|---|------|-----|------|------|
| 1 | v01_walk_escape | CVE-2021-3156 (sudo) | walk_write | VULN |
| 2 | v02_walk_safe | SAFE-ctr | walk_write | SAFE |
| 3 | v03_struct_ob1 | GENERIC-ob1 | struct_idx | VULN |
| 4 | v04_struct_safe | SAFE-str | struct_idx | SAFE |
| 5 | v05_scanf_oob | CVE-2019-7304 | unbounded_io | VULN |
| 6 | v06_scanf_bounded | SAFE-scf | unbounded_io | SAFE |
| 7 | v07_gets_oob | GENERIC-gets | unbounded_io | VULN |
| 8 | v08_nullterm | CVE-2017-1000405 | null_terminator | VULN |
| 9 | v09_nullterm_safe | SAFE-nt | null_terminator | SAFE |
| 10 | v10_calloc_wrap | CVE-2016-10165 | factory_bind | VULN |
| 11 | v11_factory_cross | GENERIC-fac | factory_bind | VULN |
| 12 | v12_factory_safe | SAFE-fac | factory_bind | SAFE |
| 13 | v13_loop_memcpy | CVE-2019-13143 | walk_write | VULN |
| 14 | v14_loop_safe | SAFE-lop | walk_write | SAFE |
| 15 | v15_ptr_arith | CVE-2021-3609 | struct_idx | VULN |
| 16 | v16_nullterm_fgets | GENERIC-nt2 | null_terminator | VULN |
| 17 | v17_memcpy_oob | CVE-2014-0160 | walk_write | VULN |
| 18 | v18_guard_miss | GENERIC-grd | struct_idx | VULN |

## 使用

```bash
# 重新生成样本 (幂等)
python _gen_samples.py

# 编译 (需 gcc)
python compile_samples.py

# 回归测试
python run_regression.py

# 单元测试 (从仓库根)
python -m pytest tests/test_hosv_ext.py -q
```

## 样本设计原则

- **VULN 样本**: 每个对应一个真实 CVE 的写模式根因, 判定需识别写模式
  并完成结构证明 (系数比较/off-by-one/格式宽度/参数绑定/终止符偏移).
- **SAFE 样本**: 与对应 VULN 样本结构几乎相同, 仅差一个关键安全属性
  (正确 +1 分配/有界输入/正确边界), 用于验证误报抑制 — 通用工具
  (如 Angr) 无法区分, 实测 6 个 SAFE 样本全部误报.
