# 格式化字符串样本元数据 - 漏洞样本与安全对照的规格定义.
#
# 每条样本: (sample_id, cve, pattern, expected, desc).
# expected ∈ confirmed|benign; 模板按 pattern 选型, 定义于 fmt_templates.py.
#

VULN = [
    ("cve_2012_0809_sudo", "CVE-2012-0809", "argv_fmt", "confirmed",
     "sudo 格式化字符串: 将 argv 直接作为 printf 格式串"),
    ("cve_2013_4118_freerdp", "CVE-2013-4118", "fprintf_argv", "confirmed",
     "FreeRDP: 网络可控字符串经 fprintf(stderr, fmt) 使用"),
    ("cve_2014_0015_curl", "CVE-2014-0015", "argv_fmt", "confirmed",
     "cURL: URL 参数作为 printf 格式串"),
    ("cve_2015_5677_bsd", "CVE-2015-5677", "global_fmt", "confirmed",
     "BSD 工具: 全局缓冲复制输入后作 printf 格式串"),
    ("cve_2015_8612_bluetooth", "CVE-2015-8612", "argv_fmt", "confirmed",
     "蓝牙驱动: 包内字符串作 printf 格式串"),
    ("cve_2016_1686_libpng", "CVE-2016-1686", "argv_fmt", "confirmed",
     "libpng: 文件名参数作 printf 格式串"),
    ("cve_2018_12020_gnupg", "CVE-2018-12020", "gets_fmt", "confirmed",
     "GnuPG: gets 读入缓冲后作 printf 格式串"),
    ("cve_2018_14618_curl", "CVE-2018-14618", "fprintf_argv", "confirmed",
     "cURL: netrc 内容经 fprintf(stderr, fmt) 使用"),
    ("cve_2019_11477_tcp", "CVE-2019-11477", "argv_fmt", "confirmed",
     "TCP 路径: 输入作 printf 格式串"),
    ("cve_2019_13631_hid", "CVE-2019-13631", "global_fmt", "confirmed",
     "HID 驱动: 事件缓冲作 printf 格式串"),
    ("cve_2020_10713_grub", "CVE-2020-10713", "argv_fmt", "confirmed",
     "GRUB: 输入作 printf 格式串"),
    ("cve_2020_27820_kernel", "CVE-2020-27820", "snprintf_fmt", "confirmed",
     "内核: 用户可控串作 snprintf 格式串"),
    ("cve_2021_3156_sudo", "CVE-2021-3156", "argv_fmt", "confirmed",
     "sudo: 命令行参数作 printf 格式串"),
    ("cve_2022_23222_perf", "CVE-2022-23222", "fprintf_argv", "confirmed",
     "perf: 事件名经 fprintf(stderr, fmt) 使用"),
    ("cve_2023_0160_audit", "CVE-2023-0160", "argv_fmt", "confirmed",
     "audit: 用户输入作 printf 格式串"),
]

SAFE = [
    ("safe_stack_const", "N/A", "stack_const", "benign",
     "栈槽常量初始化: char fmt[]=\"val=%d\" 后 printf(fmt,x) — 字面量"),
    ("safe_ptr_literal", "N/A", "ptr_literal", "benign",
     "指针指向 .rdata 字面量: const char* fmt=\"%d\" — 字面量"),
    ("safe_direct_literal", "N/A", "direct_literal", "benign",
     "直接字面量: printf(\"%s\", s) — 字面量"),
    ("safe_global_literal", "N/A", "global_literal", "benign",
     "全局只读字面量: static const char fmt[] — 字面量"),
    ("safe_snprintf_literal", "N/A", "snprintf_literal", "benign",
     "snprintf 有界字面量: snprintf(d,32,\"%s\",s) — 字面量"),
]
