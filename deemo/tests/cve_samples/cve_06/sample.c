#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Conn{int fd;char*b;void(*cb)(struct Conn*);}Conn;
Conn*active=NULL;
void on_data(Conn*c){if(c&&c->b)printf("data[%d]:%s\n",c->fd,c->b);}
void close_conn(Conn*c){if(c){free(c->b);free(c);}}
int main(void){
  active=malloc(sizeof(Conn));active->fd=3;
  active->b=strdup("payload");active->cb=on_data;
  close_conn(active);
  if(active->cb)active->cb(active); /* UAF */
  return 0;
}
