"""样本脚手架 — 对抗样本生成器的公共写入逻辑.

多个生成器 (gen_fmt_fp_samples / gen_intof_fp_samples) 复用:
  write_sample 写源码 + Makefile + README 三件套.
Makefile 按需求参数化 run 目标; README 含类型/描述/设计意图.
"""

import os


def write_sample(name, info, out_dir, run_target=True):
    """写入单个样本目录 (src/vuln.c + Makefile + README.md)."""
    d = os.path.join(out_dir, name)
    os.makedirs(os.path.join(d, "src"), exist_ok=True)
    with open(os.path.join(d, "src", "vuln.c"), "w") as f:
        f.write(info["code"])
    run_line = "\nrun: $(TARGET)\n\t./$(TARGET)\n" if run_target else ""
    makefile = f"""CC = gcc
CFLAGS = -Wall -O0 -g -no-pie -fno-stack-protector -z execstack
TARGET = vuln

all: $(TARGET)

$(TARGET): src/vuln.c
\t$(CC) $(CFLAGS) -o $@ $<

clean:
\trm -f $(TARGET)
{run_line}
.PHONY: all clean{(' run' if run_target else '')}
"""
    with open(os.path.join(d, "Makefile"), "w") as f:
        f.write(makefile)
    kind = "真实漏洞" if info.get("kind") == "vuln" else "良性样本 (误报诱发)"
    readme = f"""# {name}

- **类型**: {kind}
- **描述**: {info.get('desc', '')}
- **设计意图**: {'与 fp_ 对应样本同形态的真漏洞, 用于验证召回保持' if info.get('kind') == 'vuln' else '诱发既有检测器的典型误报根源, 用于量化误报率基线'}
"""
    with open(os.path.join(d, "README.md"), "w") as f:
        f.write(readme)
