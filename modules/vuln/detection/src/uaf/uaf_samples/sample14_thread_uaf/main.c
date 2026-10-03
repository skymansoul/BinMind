#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    char *payload;
} Task;

static Task *task_queue[4];

int main(void) {
    Task *t = (Task *)malloc(sizeof(Task));
    if (!t) return 1;
    t->id = 1;
    t->payload = (char *)malloc(32);
    if (t->payload) strcpy(t->payload, "work");
    task_queue[0] = t;
    /* UAF: free task but queue still references it */
    free(t->payload);
    free(t);
    printf("queued task id=%d\n", task_queue[0]->id);
    return 0;
}
