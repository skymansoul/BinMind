#include <stdlib.h>
char*db; int freed=0;
void async_free(){free(db);freed=1;}
int main(){db=malloc(128);async_free();if(!freed&&db)db[0]=65;return 0;}
