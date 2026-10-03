#include <stdlib.h>
static int flag=0;
void sh(){malloc(64);}
int main(){flag=1;if(flag)malloc(64);return 0;}
