/* CWE-416: UAF with struct field - free struct, use field pointer alias.
   char *alias = obj->name; free(obj); puts(alias); // use dangling alias */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { int id; char *name; } Record;
int main(void) {
    Record *r = malloc(sizeof(Record));
    r->id = 1; r->name = strdup("alpha");
    char *alias = r->name; /* alias to heap memory */
    printf("id=%d name=%s\n", r->id, alias);
    free(r->name);
    free(r);
    puts(alias); /* UAF: alias still points to freed r->name */
    return 0;
}
