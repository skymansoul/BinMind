# CVE-2014-0160 — walk_write

# CVE
CVE-2014-0160

# 判定
VULN

# 为什么有效
外部 n 可达 32, 分配仅 8 → memcpy 越界
