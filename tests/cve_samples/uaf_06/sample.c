#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct{int id;char*sdp;}Peer;
Peer*peer=NULL;
void connect_peer(){peer=malloc(sizeof(Peer));peer->id=1;peer->sdp=strdup("v=0");}
void disconnect_peer(){free(peer->sdp);free(peer);}
void send_rtp(){if(peer)printf("sending to %d",peer->id);}
int main(){connect_peer();disconnect_peer();send_rtp();return 0;}