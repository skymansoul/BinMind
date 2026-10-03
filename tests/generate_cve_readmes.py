"""Auto-generate README.md for CVE heap samples missing documentation."""
import os, sys

BASE = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE, 'heap_samples')

CVE_INFO = {
    'CVE-2014-0160_heartbleed': {
        'type': 'Heap Buffer Over-read',
        'cwe': 'CWE-126',
        'desc': (
            'OpenSSL Heartbleed — missing bounds check in TLS heartbeat extension. '
            'Attacker sends a crafted heartbeat request with a small payload but '
            'large claimed length, causing the server to read beyond the allocated '
            'buffer and leak up to 64KB of heap memory.'
        ),
        'trigger': 'Send crafted TLS heartbeat with payload_len=1, claimed_len=65535',
        'fix': 'Bounds check: verify payload_len == claimed_len before memcpy',
    },
    'CVE-2016-2177_uaf': {
        'type': 'Use-After-Free / Heap Overflow',
        'cwe': 'CWE-416/CWE-122',
        'desc': (
            'OpenSSL improper handling of pointer arithmetic in ssl3_read_bytes. '
            'Incorrect integer size used for pointer addition leads to out-of-bounds '
            'buffer access on the heap, potentially allowing remote code execution.'
        ),
        'trigger': 'Multiple concurrent SSL connections with fragmented records',
        'fix': 'Use correct integer type (size_t) for pointer offsets',
    },
    'CVE-2016-6187_apparmor': {
        'type': 'Heap Buffer Overflow',
        'cwe': 'CWE-122',
        'desc': (
            'AppArmor policy replacement heap overflow. When replacing a policy, '
            'insufficient size validation on user-supplied data allows writing '
            'past the allocated buffer, enabling local privilege escalation.'
        ),
        'trigger': 'Load a crafted AppArmor policy with oversized profile name',
        'fix': 'Add bounds check on profile name length before copy',
    },
    'CVE-2017-17052_mmap': {
        'type': 'Heap Buffer Overflow via mmap',
        'cwe': 'CWE-122',
        'desc': (
            'Linux kernel mmap region overlap. Improper handling of mmap flags '
            'allows a writable mapping to overlap with kernel heap memory, '
            'leading to kernel heap overflow and privilege escalation.'
        ),
        'trigger': 'mmap with MAP_FIXED overlapping a kernel heap region',
        'fix': 'Validate mmap address range does not overlap kernel allocations',
    },
    'CVE-2017-3732_bn': {
        'type': 'Heap Information Leak / Carry Propagation',
        'cwe': 'CWE-125',
        'desc': (
            'OpenSSL BN_mod_exp carries bug. During modular exponentiation, '
            'a carry propagation error in Montgomery multiplication leads to '
            'out-of-bounds heap read, leaking sensitive key material.'
        ),
        'trigger': 'RSA operations with specific modulus values that trigger carry bug',
        'fix': 'Fix carry propagation in BN_mod_exp_mont_consttime',
    },
    'CVE-2018-16864_systemd': {
        'type': 'Stack-based Buffer Overflow (Heap-correlated)',
        'cwe': 'CWE-770',
        'desc': (
            'systemd-journald attacker-controlled alloca(). A user-supplied '
            'size is passed to alloca() without validation, allowing stack or '
            'heap buffer overflow via journal log entries.'
        ),
        'trigger': 'Send journal log entry with oversized field to systemd-journald',
        'fix': 'Validate user-supplied allocation size against MAX_* constants',
    },
    'CVE-2019-17666_wifi': {
        'type': 'Heap Buffer Overflow',
        'cwe': 'CWE-122',
        'desc': (
            'Linux kernel WiFi (rtlwifi) driver heap overflow. When processing '
            'WiFi management frames, a missing bounds check on the P2P IE length '
            'allows writing attacker-controlled data past the heap buffer.'
        ),
        'trigger': 'Send crafted WiFi P2P action frame with oversized IE',
        'fix': 'Validate P2P IE length against remaining buffer space',
    },
    'CVE-2020-10713_grub': {
        'type': 'Heap Buffer Overflow',
        'cwe': 'CWE-122',
        'desc': (
            'GRUB2 bootloader buffer overflow in font processing. Maliciously '
            'crafted font file with large glyph dimensions causes a heap overflow '
            'during font rendering, enabling Secure Boot bypass.'
        ),
        'trigger': 'Boot with a crafted font file containing oversized glyph data',
        'fix': 'Validate glyph dimensions against allocated buffer size',
    },
    'CVE-2021-23840_evp': {
        'type': 'Heap Buffer Overflow',
        'cwe': 'CWE-190->CWE-122',
        'desc': (
            'OpenSSL EVP_PKEY_decrypt integer overflow leading to heap overflow. '
            'Crafted ciphertext with a specific length triggers an integer overflow '
            'in size computation, resulting in undersized allocation and subsequent '
            'heap buffer overflow.'
        ),
        'trigger': 'Call EVP_PKEY_decrypt with crafted ciphertext of specific length',
        'fix': 'Use overflow-safe arithmetic (size_t) for allocation size computation',
    },
    'CVE-2021-3801_croco': {
        'type': 'Heap Buffer Overflow',
        'cwe': 'CWE-122/CWE-674',
        'desc': (
            'libcroco CSS parser heap overflow. Deeply nested CSS selectors '
            'trigger unbounded recursion/stack allocation that overflows into '
            'heap, allowing DoS or potential RCE via crafted CSS.'
        ),
        'trigger': 'Parse CSS file with >10000 levels of nested selectors',
        'fix': 'Limit maximum nesting depth in CSS parser',
    },
    'CVE-2022-24834_redis': {
        'type': 'Heap Buffer Overflow',
        'cwe': 'CWE-190->CWE-122',
        'desc': (
            'Redis Lua cjson/cmsgpack heap overflow. Integer overflow in '
            'cjson array encoding allows a heap buffer overflow when encoding '
            'large arrays, leading to RCE in Redis via crafted Lua scripts.'
        ),
        'trigger': 'Execute Lua script using cjson.encode on deeply nested table',
        'fix': 'Validate array length before allocation in cjson encoder',
    },
    'CVE-2023-0286_uaf': {
        'type': 'Use-After-Free / Heap Overflow',
        'cwe': 'CWE-416/CWE-843',
        'desc': (
            'OpenSSL X.509 GeneralName type confusion. Improper handling of '
            'X.400 address type in GENERAL_NAME allows a type confusion leading '
            'to UAF or heap overflow when parsing crafted certificates.'
        ),
        'trigger': 'Parse X.509 certificate with malformed X.400 address type',
        'fix': 'Validate GENERAL_NAME type before processing its value',
    },
    'CVE-2023-6246_syslog': {
        'type': 'Heap Buffer Overflow',
        'cwe': 'CWE-122',
        'desc': (
            'glibc syslog() heap overflow. When processing formatted syslog '
            'messages with %n and oversized arguments, a heap overflow occurs '
            'in the vsyslog() internal buffer, enabling local privilege escalation.'
        ),
        'trigger': 'Call syslog() with a format string containing %n and large args',
        'fix': 'Add bounds check in __vsyslog_internal on formatted output length',
    },
}


def generate_readme(sample_dir, info):
    name = os.path.basename(sample_dir)
    lines = [
        f"# {name}",
        "",
        f"**Type:** {info['type']}  ",
        f"**CWE:** {info.get('cwe', 'CWE-122')}  ",
        "",
        "## 漏洞原理 (Vulnerability Mechanism)",
        "",
        info['desc'],
        "",
        "## 触发条件 (Trigger Condition)",
        "",
        info['trigger'],
        "",
        "## 防御建议 (Mitigation)",
        "",
        info['fix'],
        "",
        "## 构建与测试",
        "",
        "```bash",
        "make clean && make",
        "./cve.elf          # T触发漏洞",
        "./cve.elf safe     # 安全路径（若支持）",
        "```",
        "",
        "## BinMind 检测期望",
        "",
        f"- 期望类型: `{info['type']}`",
        "- 期望判定: `CONFIRMED` (Z置信度 >= 0.70)",
        "- GAPSBV Stage: Stage 4 allocator-aware verification",
        "",
    ]
    return '\n'.join(lines)


def main():
    created = 0
    for name, info in CVE_INFO.items():
        sample_dir = os.path.join(SAMPLES_DIR, name)
        readme_path = os.path.join(sample_dir, 'README.md')
        if not os.path.isdir(sample_dir):
            print(f"SKIP (no dir): {name}")
            continue
        content = generate_readme(sample_dir, info)
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"CREATED: {name}/README.md")
        created += 1
    print(f"\nDone: {created} created")


if __name__ == '__main__':
    main()
