/* uaf_11 — 文件描述符关闭后读取 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(){FILE*f=fopen("/dev/null","r");int fd=fileno(f);fclose(f);char buf[16];read(fd,buf,16);return 0;}
