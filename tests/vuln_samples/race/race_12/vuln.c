#include <fcntl.h>
#include <unistd.h>
void fk_race(){int fd=open("/tmp/x",66,384);write(fd,"x",1);write(fd,"y",1);close(fd);}
int main(){fk_race();return 0;}
