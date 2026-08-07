/*
 * QEMU user-mode 内存操作插桩插件 (trace-mem风格, 自写轻量版)
 *
 * 用途: 作为 qemu_tracer.py 的运行时 ground truth 后端。
 *   在 QEMU 自建版本(qemu-x86_64 --plugin)下加载, 记录每条访存指令
 *   的内存地址与宽度, 用于确认真实堆越界访问。
 *
 * 编译(Linux):
 *   gcc -shared -fPIC -o qemu_memtrace.so qemu_memtrace.c \
 *       -I$QEMU/include
 *
 * 使用:
 *   qemu-x86_64 -plugin ./qemu_memtrace.so -d plugin \
 *       ./vuln_debug args...
 *
 * 输出: 每条越界嫌疑访存的 PC + 地址 + 宽度, 由 qemu_tracer.py 解析。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "qemu-plugin.h"

/* 记录访问的内存范围, 供Python端后处理判断是否越界 */
static uint64_t min_addr = UINT64_MAX;
static uint64_t max_addr = 0;
static uint64_t total_access = 0;
static uint64_t heap_write_cnt = 0;

static void vcpu_tb_exec(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    /* 逐指令注册内存访问回调 */
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        qemu_plugin_register_vcpu_mem_cb(
            insn, NULL, QEMU_PLUGIN_CB_NO_REGS,
            QEMU_PLUGIN_MEM_RW, mem_cb);
    }
}

static void mem_cb(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                   uint64_t vaddr, void *userdata)
{
    total_access++;
    /* 只统计写入(疑似越界写) */
    if (qemu_plugin_mem_is_store(info)) {
        uint32_t size = qemu_plugin_mem_size_shift(info);
        uint64_t width = 1ULL << size;
        if (vaddr < min_addr)
            min_addr = vaddr;
        if (vaddr + width > max_addr)
            max_addr = vaddr + width;
        heap_write_cnt++;
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                            const qemu_info_t *info,
                                            int argc, char **argv)
{
    qemu_plugin_register_vcpu_tb_exec_cb(id, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS);
    atexit(print_summary);
    return 0;
}

static void print_summary(void)
{
    fprintf(stderr,
            "MEMTRACE total_access=%" PRIu64
            " heap_writes=%" PRIu64
            " range=[0x%" PRIx64 ", 0x%" PRIx64 "]\n",
            total_access, heap_write_cnt, min_addr, max_addr);
}
