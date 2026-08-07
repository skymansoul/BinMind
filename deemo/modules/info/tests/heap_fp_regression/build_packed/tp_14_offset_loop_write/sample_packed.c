
/* 加壳仿真: 危险API运行时解析, 隐藏导入表 */
#include <windows.h>
#include <stddef.h>
static void *(*p_malloc)(size_t);
static void *(*p_calloc)(size_t, size_t);
static void *(*p_realloc)(void *, size_t);
static void *(*p_memcpy)(void *, const void *, size_t);
static void *(*p_memmove)(void *, const void *, size_t);
static char *(*p_strcpy)(char *, const char *);
static char *(*p_strncpy)(char *, const char *, size_t);
static int (*p_sprintf)(char *, const char *, ...);
static int (*p_snprintf)(char *, size_t, const char *, ...);
static char *(*p_strcat)(char *, const char *);
static char *(*p_gets)(char *);
static long (*p_read)(int, void *, unsigned long);
static int (*p_fread)(void *, size_t, size_t, void *);
static void (*p_free)(void *);
static int (*p_scanf)(const char *, ...);
static int g_init = 0;
static void _init_apis(void) {
    if (g_init) return;
    g_init = 1;
    HMODULE m = GetModuleHandleA("msvcrt.dll");
    if (!m) m = LoadLibraryA("msvcrt.dll");
    p_malloc = (void *(*)(size_t))GetProcAddress(m, "malloc");
    p_calloc = (void *(*)(size_t, size_t))GetProcAddress(m, "calloc");
    p_realloc = (void *(*)(void *, size_t))GetProcAddress(m, "realloc");
    p_memcpy = (void *(*)(void *, const void *, size_t))GetProcAddress(m, "memcpy");
    p_memmove = (void *(*)(void *, const void *, size_t))GetProcAddress(m, "memmove");
    p_strcpy = (char *(*)(char *, const char *))GetProcAddress(m, "strcpy");
    p_strncpy = (char *(*)(char *, const char *, size_t))GetProcAddress(m, "strncpy");
    p_sprintf = (int (*)(char *, const char *, ...))GetProcAddress(m, "sprintf");
    p_snprintf = (int (*)(char *, size_t, const char *, ...))GetProcAddress(m, "snprintf");
    p_strcat = (char *(*)(char *, const char *))GetProcAddress(m, "strcat");
    p_gets = (char *(*)(char *))GetProcAddress(m, "gets");
    p_read = (long (*)(int, void *, unsigned long))GetProcAddress(m, "read");
    p_fread = (int (*)(void *, size_t, size_t, void *))GetProcAddress(m, "fread");
    p_free = (void (*)(void *))GetProcAddress(m, "free");
    p_scanf = (int (*)(const char *, ...))GetProcAddress(m, "scanf");
}

/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
int main(void) { _init_apis(); 
    char *buf = (char *)p_malloc(64);
    if (!buf) return -1;
    int i = 0;
    while (i < 128) { buf[i++] = 'J'; }
    p_free(buf);
    return 0;
}
