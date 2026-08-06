/* CWE-121: Stack overflow via longjmp with corrupted stack frame */
#include <stdio.h>
#include <setjmp.h>
#include <string.h>
static jmp_buf env;
void middle(char *input) {
    char buf[32]; strcpy(buf, input); /* overflow here */
    longjmp(env, 1);
}
int main(void) {
    if (setjmp(env) == 0) middle("AAAA...");
    else printf("recovered\n");
    return 0;
}
