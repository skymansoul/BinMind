# GENERIC-grd — struct_idx

# CVE
GENERIC-grd

# 判定
VULN

# 为什么有效
守卫 n<=100 仅钳制上限, 分配仅 50 个元素; n 取 51..100 时循环写越界
