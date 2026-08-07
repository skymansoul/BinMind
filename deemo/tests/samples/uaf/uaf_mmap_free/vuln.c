#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
/* UAF-14: mmap/munmap的UAF — 非堆分配释放后访问 */
int main(void) {
    long pgsize = sysconf(_SC_PAGESIZE);
    char *buf = (char *)mmap(NULL, pgsize, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) return 1;
    strcpy(buf, "mmap_data");
    munmap(buf, pgsize);
    printf("after munmap: %s\n", buf);  /* VULNERABLE: munmap后访问 */
    return 0;
}
