/* stack_overflow_07 ¡ª strcatÀÛ»ýÒç³ö */
#include <stdio.h>
#include <string.h>
int main() { char buf[32]={0}; strcat(buf,"AAAAAAAA"); strcat(buf,"BBBBBBBB"); strcat(buf,"CCCCCCCC"); strcat(buf,"DDDDDDDD"); strcat(buf,"EEEEEEEE"); return 0; }
