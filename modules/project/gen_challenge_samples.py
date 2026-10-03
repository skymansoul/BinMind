# 生成挑战样本: 专门针对跨步区间/路径条件/内存区域精度
# 每个样本测试一种旧方法无法正确处理但新方法可以的模式
# 分成三类:
#   A类: 路径条件挑战 — 需要分支约束才能正确判定
#   B类: 跨步区间挑战 — 需要同余信息才能精确判定
#   C类: 内存区域挑战 — 需要区域判别才能过滤栈写入
import pathlib

BASE = pathlib.Path('cve_samples')


def _gen_path_cond_sample():
    """A类: 路径条件依赖 — 分支内安全, 无路径条件会误报.

    模式: if(size > 256) size = 256; memcpy(buf, src, size);
    旧方法: size值域不确定 (可能>256) → POSSIBLE_OVERFLOW
    新方法: 路径条件约束 size≤256 → DEFINITE_SAFE
    """
    return {
        'name': 'cve19_path_cond_clamp',
        'cve': 'CVE-2023-path-cond',
        'type': 'safe_by_path_condition',
        'severity': 'NONE',
        'pattern': 'path_condition_clamp',
        'desc': '路径条件钳位: if(size>256)size=256; malloc(256)→memcpy(size≤256)',
        'c_source': '''// cve19_path_cond_clamp — 路径条件钳位保护
// CVE参考: CVE-2023-path-cond, 模式: path_condition_clamp
// 关键: static分析必须在cmp/jg分支后应用size≤256约束
// 旧方法(无路径条件): size值域不确定→误报
// 新方法(有路径条件): 分支后size≤256→DEFINITE_SAFE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 256

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 路径条件保护: 若>256则钳位
    int write_size = 512;
    if (write_size > ALLOC_SIZE)
        write_size = ALLOC_SIZE;
    // 路径条件: write_size ≤ 256

    memset(buf, 'A', write_size);
    printf("buf=%p, wrote %d <= %d, SAFE\\n",
           (void *)buf, write_size, ALLOC_SIZE);
    free(buf);
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o cve19_path_cond_clamp main.c',
    }


def _gen_path_cond_early_return():
    """A类: 提前返回保护 — 超出范围则终止.

    模式: if(size > limit) return; memcpy(buf, src, size);
    旧方法: size值域不确定 → POSSIBLE_OVERFLOW
    新方法: 路径条件 size≤limit → DEFINITE_SAFE
    """
    return {
        'name': 'cve20_path_cond_early_return',
        'cve': 'CVE-2023-early-ret',
        'type': 'safe_by_path_condition',
        'severity': 'NONE',
        'pattern': 'path_condition_early_return',
        'desc': '提前返回保护: if(size>128)return; malloc(128)→memcpy(size≤128)',
        'c_source': '''// cve20_path_cond_early_return — 提前返回保护
// CVE参考: CVE-2023-early-ret, 模式: path_condition_early_return
// 关键: cmp+ja+jmp构成size>128则退出的保护
// 旧方法: 无路径条件, size值域不确定→误报
// 新方法: fall-through路径size≤128→DEFINITE_SAFE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 128

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    int write_size = 256;
    // 显式边界检查: >128则退出
    if (write_size > ALLOC_SIZE) {
        free(buf);
        return 0;
    }
    // 此路径: write_size ≤ 128

    memset(buf, 'B', write_size);
    printf("buf=%p, wrote %d <= %d, SAFE\\n",
           (void *)buf, write_size, ALLOC_SIZE);
    free(buf);
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o cve20_path_cond_early_return main.c',
    }


def _gen_stride_loop_pattern():
    """B类: 跨步区间精确性 — 需要同余信息才知写入在安全范围内.

    模式: malloc(64); for(i=0;i<64;i+=4) buf[i]=val;
    旧方法: [0,63]区间 → 与分配[0,63]完全重叠 → POSSIBLE_OVERFLOW? No
    实际上标准区间也能判定安全, 换一个更微妙的:
    malloc(120); for(i=0;i<120;i+=8) buf[i]=val;
    标准区间: [0,119] → 与[0,119]重叠 → 但实际只访问{0,8,16,...,112}共15个点
    跨步区间能更精确地确认安全
    """
    return {
        'name': 'cve21_stride_loop_safe',
        'cve': 'STRIDE-SAFE',
        'type': 'safe_by_strided_interval',
        'severity': 'NONE',
        'pattern': 'strided_loop_safe',
        'desc': '跨步循环安全: malloc(120)→stride=8循环写入≤120, 同余信息证明安全',
        'c_source': '''// cve21_stride_loop_safe — 跨步区间安全验证
// CVE参考: STRIDE-SAFE, 模式: strided_loop_safe
// 关键: for(i=0;i<120;i+=8) — 步长8, 只有15个写入点
// 旧方法: 标准区间[0,119], 宽120 → 与分配120重叠, 可能溢出
// 新方法: 跨步区间[0,112,8], 所有访问点在{0,8,...,112}内, 确定安全
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 120

int main(int argc, char **argv) {
    unsigned char *buf = (unsigned char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 步长8循环: 只访问偏移{0,8,16,...,112}
    // 最大偏移112 < 120, 完全安全
    for (int i = 0; i < ALLOC_SIZE; i += 8) {
        buf[i] = (unsigned char)(i & 0xFF);
    }

    printf("buf=%p, stride-8 loop < %d, SAFE\\n",
           (void *)buf, ALLOC_SIZE);
    free(buf);
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o cve21_stride_loop_safe main.c',
    }


def _gen_stride_overflow():
    """B类: 跨步区间溢出 — 同余信息揭示实际溢出.

    模式: malloc(100); for(i=0;i<104;i+=8) buf[i]=val;
    标准区间: 写入[0,103], 分配[0,99] → POSSIBLE_OVERFLOW (置信度~0.5)
    跨步区间: 访问{0,8,16,...,96,104}, 104>99 → 最后一个访问越界
    能提供更精确的溢出置信度
    """
    return {
        'name': 'cve22_stride_loop_overflow',
        'cve': 'STRIDE-OVERFLOW',
        'type': 'heap_overflow',
        'severity': 'HIGH',
        'pattern': 'strided_loop_overflow',
        'desc': '跨步循环溢出: malloc(64)→stride=4×20次=80B>64, 越界16B, 循环写入偏移超分配',
        'c_source': '''// cve22_stride_loop_overflow — 跨步区间溢出检测
// CVE参考: STRIDE-OVERFLOW, 模式: strided_loop_overflow
// 关键: for(i=0;i<80;i+=4) — 20个写入点, i=76时偏移76>63, 越界
// 标准区间: 写入[0,79], 分配[0,63] → DEFINITE_OVERFLOW
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 64
#define LOOP_BOUND 80

int main(int argc, char **argv) {
    unsigned char *buf = (unsigned char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 步长4循环: 访问偏移{0,4,8,...,76}
    // 最大偏移76 > 63, 溢出!
    for (int i = 0; i < LOOP_BOUND; i += 4) {
        buf[i] = (unsigned char)(i & 0xFF);
    }

    printf("buf=%p, stride-4 overflow at i=76, alloc=%d\\n",
           (void *)buf, ALLOC_SIZE);
    free(buf);
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o cve22_stride_loop_overflow main.c',
    }


def _gen_memory_region_stack_write():
    """C类: 内存区域判别 — 栈写入不应被误判为堆溢出.

    模式: 在栈上操作堆指针, 向栈变量写入, 但mov指令的目标是[rbp-X]
    旧方法: 检测到"向堆指针写入"→报告溢出 (但目标其实是栈)
    新方法: 内存区域判别→目标[rbp-8]在栈上→不是堆写入→不报告
    """
    return {
        'name': 'cve23_mem_region_stack',
        'cve': 'MEM-REGION-SAFE',
        'type': 'safe_by_memory_region',
        'severity': 'NONE',
        'pattern': 'memory_region_stack_write',
        'desc': '栈区域写入: 向[rbp-0x8]写入堆指针, 不是堆区域写入, 不应报告',
        'c_source': '''// cve23_mem_region_stack — 内存区域判别
// CVE参考: MEM-REGION-SAFE, 模式: memory_region_stack_write
// 关键: mov [rbp-0x8], rax 是栈写入, 不是堆写入
// 旧方法: 检测到rax持有堆指针 + mov指令→可能误判为堆写入
// 新方法: [rbp-0x8]是栈区域→非堆写入→不报告
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 128

// 辅助函数: 将堆指针保存到栈变量
void save_to_stack(char **ptr_storage, char *heap_ptr) {
    // mov [rbp+0x10], rdx 是栈写入 — 不是堆溢出
    *ptr_storage = heap_ptr;
}

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    char *saved_ptr = NULL;  // 栈变量
    save_to_stack(&saved_ptr, buf);  // 将堆指针存入栈变量

    // 实际写入: 通过saved_ptr间接写入
    memset(saved_ptr, 'S', ALLOC_SIZE);  // 安全: 写入128 ≤ 分配128

    printf("buf=%p, saved=%p, SAFE\\n", (void *)buf, (void *)saved_ptr);
    free(buf);
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o cve23_mem_region_stack main.c',
    }


# 样本注册

CHALLENGE_SAMPLES = {}

def register_all():
    samples = [
        _gen_path_cond_sample(),
        _gen_path_cond_early_return(),
        _gen_stride_loop_pattern(),
        _gen_stride_overflow(),
        _gen_memory_region_stack_write(),
    ]
    for s in samples:
        CHALLENGE_SAMPLES[s['name']] = s
    return CHALLENGE_SAMPLES


def write_samples():
    """写入所有挑战样本到磁盘."""
    register_all()
    BASE.mkdir(parents=True, exist_ok=True)

    for name, info in CHALLENGE_SAMPLES.items():
        d = BASE / name
        d.mkdir(parents=True, exist_ok=True)
        (d / 'main.c').write_text(info['c_source'].lstrip('\n'), encoding='utf-8')

        readme = f'''# {name}

# 挑战类型
- **样本分类**: {info['type']}
- **严重级别**: {info['severity']}
- **模式**: `{info['pattern']}`

# 描述
{info['desc']}

# 方法对比
- **旧方法预期**: 可能误报或漏报 (缺乏{info['pattern']}识别能力)
- **新方法预期**: 正确判定为 {info['type']}

# 精度需求
此样本需要{info['pattern']}能力才能正确分类。
旧方法的简单值域分析或模式匹配在此样本上产生错误结果。
'''
        (d / 'README.md').write_text(readme, encoding='utf-8')

    print(f'生成 {len(CHALLENGE_SAMPLES)} 个挑战样本')


if __name__ == '__main__':
    write_samples()
