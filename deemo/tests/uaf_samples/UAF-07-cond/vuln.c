#include <stdlib.h>
char*q=NULL;
void x(){q=malloc(16);}
void y(int flag){if(flag)free(q);}
void z(){q[0]=0;}
int main(){x();y(1);z();return 0;}