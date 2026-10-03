#include <stdlib.h>
void vuln(int x){char*b=malloc(64);if(x>0)memset(b,0,64);printf("%02x",b[0]);}
int main(){vuln(0);}