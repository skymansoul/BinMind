static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_test_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    void *p = malloc(64);
    if (!p) return;
    volatile_vuln_sink = p;
    __asm__ __volatile__("" : "+r"(count));
    typedef struct {{ void *data; int len; }} Obj;
    Obj obj; obj.data = p; obj.len = 64;
    void *alias = obj.data;  /* 结构体字段别名 */
    free(obj.data);
    free(alias);  /* double free via struct field alias */
    printf("v_test: done\n");
}
__attribute__((noinline))
void v_test_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    void *p = malloc(64);
    if (!p) return;
    volatile_vuln_sink = p;
    __asm__ __volatile__("" : "+r"(count));
    typedef struct {{ void *data; int len; }} Obj;
    Obj obj; obj.data = p; obj.len = 64;
    free(obj.data);
    obj.data = NULL;  /* 清除字段 */
    printf("v_test: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("double free test\n");
    v_test_vuln(count);
    v_test_safe(count);
    return 0;
}