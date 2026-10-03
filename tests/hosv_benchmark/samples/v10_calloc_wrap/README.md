# CVE-2016-10165 — factory_bind

# CVE
CVE-2016-10165

# 判定
VULN

# 为什么有效
65536*65536 溢出 32-bit size_t → 返回 0 或过小对象
