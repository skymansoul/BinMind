/* GENERIC-race-umask CWE-362: umask后创建文件——umask-创建之间的竞态 */
#include <sys/stat.h>
#include <fcntl.h>
void umask_race(){mode_t old=umask(0);int fd=open("/tmp/x",O_CREAT|O_WRONLY,0600);umask(old);close(fd);}
int main(){umask_race();return 0;}
