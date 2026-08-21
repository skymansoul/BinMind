/*
 * cve_2019_2215 — Android Binder UAF (CWE-416)
 * 模式: 释放后经全局指针解引用.
 * 原漏洞: binder 线程退出时 freed wait queue 仍被引用, 提权利用.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char *g_ptr;
void init() { g_ptr = malloc(256); memcpy(g_ptr, "data", 4); }
void cleanup() { free(g_ptr); g_ptr = NULL; /* FIX: NULL assignment removed for demo */ }
void use() { if(g_ptr) printf("data: %s", g_ptr); } /* UAF */
int main() { init(); cleanup();
    /* re-establish dangling pointer: */ g_ptr = (char*)0x41414141;
    use(); return 0; }
