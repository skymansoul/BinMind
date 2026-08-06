/* GENERIC-race-stat-open CWE-367: stat后open——文件属性可能在检查后改变 */
#include <sys/stat.h>
#include <fcntl.h>
void so(char*p){struct stat st;if(stat(p,&st)==0&&S_ISREG(st.st_mode)){int fd=open(p,O_RDONLY);close(fd);}}
int main(int c,char**v){so(c>1?v[1]:"/tmp/x");return 0;}
