/* CVE-2016-10150 KVM kvm_ioctl_create_device: 释放设备对象后经函数返回指针继续打印. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    printf("%s\n", p);
    return 0;
}
