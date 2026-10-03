#include <stdio.h>
#include <stdlib.h>
/* INTOF-05: 循环计数器回绕 — char/short循环计数器溢出导致无限循环
 * CWE-190: Integer Overflow in loop counter */
int main(void) {
    char buf[300];
    /* VULNERABLE: i是unsigned char, 范围[0,255], 永远<300, 死循环 */
    for (unsigned char i = 0; i < 300; i++) {
        buf[i] = (char)i;  /* i=256时buf越界 */
    }
    printf("done\n");
    return 0;
}
