#include <stdio.h>
#include <stdlib.h>
struct task{void *data;int done;};void run(struct task *t){t->done=1;}
int main(){struct task *t=malloc(sizeof(*t));run(t);free(t);run(t);return 0;}
