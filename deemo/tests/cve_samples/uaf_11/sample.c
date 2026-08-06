#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct{char*ticket;int ver;}TLSSession;
TLSSession*tls=NULL;
void create_ticket(){tls=malloc(sizeof(TLSSession));tls->ticket=strdup("ticket123");tls->ver=3;}
void invalidate_ticket(){free(tls->ticket);free(tls);}
void resume_session(){if(tls)printf("resume v%d",tls->ver);}
int main(){create_ticket();invalidate_ticket();resume_session();return 0;}