/* CWE-121: Stack buffer overflow via scanf("%s") unbounded read */
#include <stdio.h>
int main(void) {
    char name[32];
    printf("Enter name: ");
    scanf("%s", name); /* no width limit */
    printf("Hello %s\n", name);
    return 0;
}
