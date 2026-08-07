/**
 * CVE-2019-19532 — Linux HID driver UAF via hiddev_disconnect race
 * UAF模式: struct_field_uaf
 *
 * 样本设计:
 *   精简化复现该CVE的核心UAF机制.
 *   保留原始漏洞的数据流结构: malloc→free→use.
 *   去除平台特定代码, 仅保留可静态分析的user-space等价逻辑.
 *
 * 对静态分析具有挑战性的原因:
 *   1. free和use可能在不同的执行路径上 (路径敏感)
 *   2. 指针可能通过全局变量/栈/寄存器间接到use (别名分析)
 *   3. free后可能有NULL赋值但走不到use (条件分析)
 *   4. 跨函数free→use传播 (过程间分析)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int len; char *data; void (*cb)(void);
} Obj_v_2019_19532_hid;
static Obj_v_2019_19532_hid *g_obj_v_2019_19532_hid;

void v_2019_19532_hid_make(void) {
    g_obj_v_2019_19532_hid = (Obj_v_2019_19532_hid *)malloc(sizeof(Obj_v_2019_19532_hid));
    if (g_obj_v_2019_19532_hid) {
        g_obj_v_2019_19532_hid->len = 256;
        g_obj_v_2019_19532_hid->data = (char *)malloc(256);
        g_obj_v_2019_19532_hid->cb = NULL;
    }
}

void v_2019_19532_hid_destroy(void) {
    if (g_obj_v_2019_19532_hid) {
        free(g_obj_v_2019_19532_hid->data); free(g_obj_v_2019_19532_hid);
    }
}

void v_2019_19532_hid_use(void) {
    if (g_obj_v_2019_19532_hid && g_obj_v_2019_19532_hid->data)
        printf("%c", g_obj_v_2019_19532_hid->data[0]);  /* UAF */
}

int main(void) {
    printf("=== v_2019_19532_hid struct field UAF ===\n");
    v_2019_19532_hid_make(); v_2019_19532_hid_destroy(); v_2019_19532_hid_use();
    return 0;
}

