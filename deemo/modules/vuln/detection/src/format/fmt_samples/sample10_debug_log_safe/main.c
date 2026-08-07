#include <stdio.h>

int main(void) {
    int status = 42;
    /* SAFE: constant debug format */
    printf("[DEBUG] status=%d\n", status);
    printf("[INFO] initialization complete\n");
    printf("[WARN] threshold exceeded: %d\n", 100);
    return 0;
}
