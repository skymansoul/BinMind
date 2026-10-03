/* FMT TN (safe) sample */
#include <stdio.h>
static const char *kMsg = "state: %d\n";
int main(void) {
    printf(kMsg, 3);
    printf("done\n");
    return 0;
}
