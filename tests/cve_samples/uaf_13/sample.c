#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct{int kid;char*key;}KeyHandle;
KeyHandle*kh=NULL;
void gen_key(){kh=malloc(sizeof(KeyHandle));kh->kid=42;kh->key=strdup("deadbeef");}
void destroy_key(){free(kh->key);free(kh);}
void sign_data(){if(kh)printf("sign with k%d",kh->kid);}
int main(){gen_key();destroy_key();sign_data();return 0;}