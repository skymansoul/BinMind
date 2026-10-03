/* CVE-2013-4788: Android dlfree/rtld heap overflow via crafted ELF */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_phdr(size_t phnum, size_t phentsize, const char *data) {
    /* BUG: phnum * phentsize may overflow */
    size_t alloc_sz = phnum * phentsize;
    if (alloc_sz == 0 || alloc_sz > 0x100000) alloc_sz = 0x1000;
    char *buf = (char *)malloc(alloc_sz);
    if (!buf) return;
    /* 实际需要的大小可能 > alloc_sz */
    size_t real_sz = (size_t)phnum * (size_t)phentsize;
    if (real_sz > alloc_sz) {
        memcpy(buf, data, real_sz);  /* heap overflow */
    } else {
        memcpy(buf, data, alloc_sz);
    }
    free(buf);
}

int main(int argc, char **argv) {
    size_t phnum = 1024, phentsize = 56;
    if (argc >= 3) { phnum = (size_t)atol(argv[1]); phentsize = (size_t)atol(argv[2]); }
    char *data = (char *)calloc(phnum, phentsize);
    if (data) { memset(data, 'E', phnum * phentsize); process_phdr(phnum, phentsize, data); free(data); }
    printf("done\n");
    return 0;
}
