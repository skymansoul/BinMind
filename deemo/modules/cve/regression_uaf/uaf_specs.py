# UAF 样本元数据 — 漏洞样本与安全对照的规格定义.
#
# 每条样本: (sample_id, cve, pattern, expected, desc).
# expected ∈ confirmed|benign; 模板按 pattern 选型, 定义于 uaf_templates.py.
#
# 创建: 2025-05-12

VULN = [
    ("cve_2016_10150_kvm", "CVE-2016-10150", "printf_use", "confirmed",
     "KVM kvm_ioctl_create_device: 释放设备对象后经函数返回指针继续打印"),
    ("cve_2017_2636_n_hdlc", "CVE-2017-2636", "strlen_use", "confirmed",
     "n_hdlc 驱动: 竞争路径释放对象后 strlen 读取"),
    ("cve_2017_7533_inode", "CVE-2017-7533", "printf_use", "confirmed",
     "内核 inode 引用计数缺陷: 释放后经 printf 使用"),
    ("cve_2018_17182_vmacache", "CVE-2018-17182", "memcpy_use", "confirmed",
     "vmacache: 键误匹配导致释放对象被 memcpy 读取"),
    ("cve_2018_7566_alsa_timer", "CVE-2018-7566", "memset_use", "confirmed",
     "ALSA timer: snd_timer_user 释放后 memset 写入"),
    ("cve_2019_15291_brcmfmac", "CVE-2019-15291", "memcpy_use", "confirmed",
     "Broadcom brcmfmac: 释放缓冲区后 memcpy 读入"),
    ("cve_2019_19532_hid", "CVE-2019-19532", "printf_use", "confirmed",
     "HID debug 事件: 释放后打印缓冲内容"),
    ("cve_2019_2215_binder", "CVE-2019-2215", "write_deref", "confirmed",
     "Android Binder: 释放 task_struct 后写入其字段"),
    ("cve_2020_0022_bluetooth", "CVE-2020-0022", "strlen_use", "confirmed",
     "Bluetooth L2CAP: 释放 skb 后 strlen 计算长度"),
    ("cve_2020_14386_afpacket", "CVE-2020-14386", "memcpy_use", "confirmed",
     "AF_PACKET tpacket: 释放后 memcpy 越界读"),
    ("cve_2020_25211_netfilter", "CVE-2020-25211", "printf_use", "confirmed",
     "netfilter nftables: 释放规则后打印"),
    ("cve_2021_32399_blk", "CVE-2021-32399", "memset_use", "confirmed",
     "块层 blk-mq: 释放请求后 memset 清零"),
    ("cve_2021_34866_ebpf", "CVE-2021-34866", "strlen_use", "confirmed",
     "eBPF 验证器: 释放 map 后 strlen 访问"),
    ("cve_2022_0995_watch_queue", "CVE-2022-0995", "printf_use", "confirmed",
     "watch_queue filter: 释放后经 printf 使用"),
    ("cve_2023_0461_io_uring", "CVE-2023-0461", "memcpy_use", "confirmed",
     "io_uring: 释放固定文件表后 memcpy 访问"),
]

SAFE = [
    ("safe_01_reborn_via_call", "N/A", "reborn_call", "benign",
     "指针经函数返回值复活: free(p); p=get_ptr(); 使用 p — 非 UAF"),
    ("safe_02_reborn_via_malloc", "N/A", "reborn_malloc", "benign",
     "指针经重新 malloc 复活: free(p); p=malloc(64); 使用 p — 非 UAF"),
    ("safe_03_nulled", "N/A", "nulled_guard", "benign",
     "free(p); p=NULL; 守卫内使用 — 防御性置空"),
    ("safe_04_errpath", "N/A", "error_path", "benign",
     "free 位于错误分支, 正常路径使用 — 路径互斥"),
    ("safe_05_cleanup", "N/A", "cleanup", "benign",
     "释放结构体后读取字段指针用于二次 free — cleanup 语义"),
]
