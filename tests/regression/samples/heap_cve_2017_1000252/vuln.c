/* CVE-2017-1000252 — KVM async page fault heap overflow
 * Pattern: 分配后 unchecked copy — 经典堆溢出模式
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct kvm_vcpu { char padding[128]; char *io_buf; int io_size; };
void process_io(struct kvm_vcpu *vcpu, char *data, int data_len) {
    vcpu->io_buf = (char *)malloc(256);
    /* BUG: data_len 可能 > 256 */
    memcpy(vcpu->io_buf, data, data_len);
}

int main(int argc, char **argv) {
    struct kvm_vcpu vcpu; memset(&vcpu, 0, sizeof(vcpu));
    char input[512]; memset(input, 'A', sizeof(input));
    int len = argc > 1 ? atoi(argv[1]) : 512;
    process_io(&vcpu, input, len);
    return 0;
}
