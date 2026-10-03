#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct{char*token;int uid;}Session;
Session*sess=NULL;
void login(){sess=malloc(sizeof(Session));sess->token=strdup("abc123");sess->uid=100;}
void logout(){free(sess->token);free(sess);}
void check_auth(){if(sess)printf("uid=%d",sess->uid);}
int main(){login();logout();check_auth();return 0;}