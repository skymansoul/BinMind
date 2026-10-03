/*
 * TP_guarded_write: True Positive — write IS guarded, should NOT trigger.
 *
 * This is a NEGATIVE test case: malloc + guarded write.
 * A naive detector would flag the buf[idx]=x as overflow (dynamic index),
 * but GAPSBV should recognize the if(idx < 64) guard and FILTER it.
 *
 * Purpose: measure false positive reduction from guard inference.
 */

#include <stdio.h>
#include <stdlib.h>

void safe_write(int idx, char value) {
    char *buf = (char *)malloc(64);
    if (!buf) return;

    /* Guards the write — static analysis MUST recognize this pattern */
    if (idx < 64 && idx >= 0) {
        buf[idx] = value;
    }

    printf("buf[%d] = %c\n", idx, buf[idx]);
    free(buf);
}

int main(int argc, char **argv) {
    int idx = (argc > 1) ? atoi(argv[1]) : 10;
    safe_write(idx, 'X');
    return 0;
}
