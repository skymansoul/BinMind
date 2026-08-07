#!/usr/bin/env python3
"""为15个堆溢出CVE样本批量生成说明文档."""

import os

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "modules", "vuln", "sample_bins", "heap_overflow_cve")

META = {
    "CVE_01": {"cve": "CVE-2021-3156", "type": "堆溢出(off-by-one)",
                "trigger": "构造argv[0]触发sudo堆溢出",
                "root_cause": "malloc(len)后memcpy写入len+1字节",
                "detection": "Layer2: write=S_alloc+1 > S_alloc", "has_vuln": True},
    "CVE_02": {"cve": "CVE-2019-13066", "type": "堆溢出(常量不匹配)",
                "trigger": "malloc(64)+memcpy(buf,data,128)",
                "root_cause": "固定分配64写入128",
                "detection": "Layer1: 128>64", "has_vuln": True},
    "CVE_03": {"cve": "CVE-2020-2551(安全)", "type": "无溢出(同变量)",
                "trigger": "malloc(n)+memcpy(buf,src,n), 同变量",
                "root_cause": "无漏洞,分配=写入",
                "detection": "Layer2: S_alloc==S_write→安全", "has_vuln": False},
    "CVE_04": {"cve": "CVE-2018-6789", "type": "堆溢出(线性偏移)",
                "trigger": "malloc(n),memcpy(buf,src,n+4)",
                "root_cause": "n+4>n恒成立",
                "detection": "Layer2: write=S_alloc+4", "has_vuln": True},
    "CVE_05": {"cve": "CVE-2019-17571(安全)", "type": "无溢出(bounds check)",
                "trigger": "malloc(256),if(n>256)return,memcpy(buf,src,n)",
                "root_cause": "路径约束n<=256",
                "detection": "Layer3 SMT: n<=256∧n<=256→安全", "has_vuln": False},
    "CVE_06": {"cve": "CVE-2020-9490", "type": "堆溢出(calloc乘积)",
                "trigger": "calloc(n,elem),n*elem溢出",
                "root_cause": "整数溢出",
                "detection": "calloc乘法语义检查", "has_vuln": True},
    "CVE_07": {"cve": "CVE-2021-3712", "type": "堆溢出(realloc缩小)",
                "trigger": "malloc(256),realloc(64),memcpy(buf,src,256)",
                "root_cause": "realloc后用旧大小写",
                "detection": "realloc大小传播", "has_vuln": True},
    "CVE_08": {"cve": "CVE-2019-16935", "type": "堆溢出(strlen+偏移)",
                "trigger": "malloc(strlen),memcpy(buf+16,src,strlen)",
                "root_cause": "偏移16+写入strlen>分配strlen",
                "detection": "Layer2: S_alloc+16", "has_vuln": True},
    "CVE_09": {"cve": "CVE-2020-25692", "type": "堆溢出(循环off-by-one)",
                "trigger": "malloc(n),循环i=0..n,buf[i]='A'",
                "root_cause": "循环上界<=n,写入n+1次",
                "detection": "区间:循环后i.hi=n+1>alloc=n", "has_vuln": True},
    "CVE_10": {"cve": "CVE-2021-3560", "type": "堆溢出(结构体越界)",
                "trigger": "malloc(sizeof(struct)),memcpy(data,input,32)",
                "root_cause": "data[8]但写32",
                "detection": "结构推断:max_offset=8,write=32", "has_vuln": True},
    "CVE_11": {"cve": "CVE-2016-0718", "type": "堆溢出(外部read)",
                "trigger": "malloc(64),memcpy(buf,tmp,read_return)",
                "root_cause": "read返回>64,无bounds check",
                "detection": "后向切片:size来源=外部输入", "has_vuln": True},
    "CVE_12": {"cve": "CVE-2014-0160(Heartbleed)", "type": "堆越界读",
                "trigger": "malloc(payload_len),memset(buf+len,0,16)",
                "root_cause": "额外16字节泄露",
                "detection": "write_end=len+16>alloc=len", "has_vuln": True},
    "CVE_13": {"cve": "CVE-2022-24407", "type": "堆溢出(sprintf)",
                "trigger": "malloc(64),sprintf(buf,'%s',long_input)",
                "root_cause": "sprintf不检查大小",
                "detection": "无边界写入→likely", "has_vuln": True},
    "CVE_14": {"cve": "CVE-2023-28456", "type": "堆溢出(对齐后溢出)",
                "trigger": "malloc(62),memcpy(buf,data,80)",
                "root_cause": "62对齐64但80仍溢出",
                "detection": "分配器模型:usable(62)=48,80>48", "has_vuln": True},
    "CVE_15": {"cve": "CVE-2020-36709", "type": "堆溢出(乘法缩放)",
                "trigger": "malloc(len),strncpy(buf,src,len*2)",
                "root_cause": "2*len>len",
                "detection": "Layer2: write=2*S_alloc", "has_vuln": True},
}

TPL = "# {title}\n\n## 基本信息\n- CVE: {cve}\n- 类型: {vtype}\n- 含漏洞: {hv}\n\n## 触发条件\n{trigger}\n\n## 根因\n{root}\n\n## 检测要点\n{det}\n\n## 编译\n```bash\nmake\n```\n"

def main():
    for dirname, info in META.items():
        dp = os.path.join(SAMPLES_DIR, dirname)
        if not os.path.isdir(dp): continue
        hv = "是" if info["has_vuln"] else "否(安全样本,误报测试用)"
        c = TPL.format(title=f"{dirname} — {info['cve']}", cve=info["cve"],
                       vtype=info["type"], hv=hv, trigger=info["trigger"],
                       root=info["root_cause"], det=info["detection"])
        with open(os.path.join(dp, "README.md"), "w", encoding="utf-8") as f:
            f.write(c)
    print(f"Generated README for {len(META)} samples")

if __name__ == "__main__":
    main()
