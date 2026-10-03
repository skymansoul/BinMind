/* DCG-FP-001: alloc_size和copy_size通过不同寄存器链传递
 * 仅DCG可通过MOV链证明两者相等→判为安全
 * alloc_size=256→rdi→rax→rbx; copy_size=256→rdi→ecx→rdx
 * 值流引擎能看到各自的常量256, 但无法证明rbx和rdx的关系
 * DCG通过rdi→rax→rbx和rdi→ecx→rdx链可证rbx=rdi=rdx→copy=alloc
 */
#include <stdlib.h>
#include <string.h>

void vuln_register_chain(int input_size) {
    // alloc_size通过rax→rbx→rsi链传递
    int alloc_size = 256;
    if (input_size > 0) alloc_size = input_size;

    char *buf = (char *)malloc(alloc_size);
    if (!buf) return;

    // copy_size通过相同的源值传递但走不同寄存器
    int copy_size = alloc_size;  // 编译器会用不同寄存器

    // 预期: DCG通过MOV链可证copy_size = alloc_size → SAFE
    // 值流引擎: 两边都追踪到alloc_size变量→也可能判同源
    // 但若编译器将copy_size放入不同寄存器链, DCG仍可通过传递闭包证明
    memcpy(buf, "test", copy_size < 256 ? copy_size : 256);

    free(buf);
}

int main() {
    vuln_register_chain(128);
    return 0;
}
