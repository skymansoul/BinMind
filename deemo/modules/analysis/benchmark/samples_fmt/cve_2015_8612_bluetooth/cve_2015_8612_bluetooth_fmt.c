/**
 * CVE-2015-8612 — BlueZ bluetoothd passes device name to sprintf as format string
 * 模式: struct_field_fmtstr
 *
 * 样本设计: 精简化复现格式字符串漏洞核心机制.
 * 对静态分析的挑战:
 *   1. 格式字符串来源需追踪 (寄存器/栈/全局/跨函数)
 *   2. 字面量格式字符串应被过滤 (误报控制)
 *   3. 跨函数传播需参数追踪
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[64];
    int id;
} Dev_v_2015_8612_bluetooth;

void v_2015_8612_bluetooth_show(Dev_v_2015_8612_bluetooth *d) {
    printf(d->name);  /* BUG: name字段可能含格式说明符 */
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    Dev_v_2015_8612_bluetooth *d = (Dev_v_2015_8612_bluetooth *)malloc(sizeof(Dev_v_2015_8612_bluetooth));
    if (d) {
        strncpy(d->name, argv[1], 63);
        d->name[63] = '\0';
        d->id = 1;
        printf("=== v_2015_8612_bluetooth struct fmt test ===\n");
        v_2015_8612_bluetooth_show(d);
        free(d);
    }
    return 0;
}

