/* UAF-08: Struct field use-after-free — free struct, use struct field (TP) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char *name;
    int  age;
} Person;

void process(void) {
    Person *p = (Person *)malloc(sizeof(Person));
    if (!p) return;
    p->name = strdup("Alice");
    p->age = 30;
    free(p);
    /* BUG: p->name points into freed struct */
    printf("name=%s age=%d\n", p->name, p->age);
}

int main(void) {
    process();
    return 0;
}
