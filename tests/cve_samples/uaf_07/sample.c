#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct{int row;char*data;}Cursor;
Cursor*cur=NULL;
void open_cursor(){cur=malloc(sizeof(Cursor));cur->row=0;cur->data=strdup("row0");}
void close_cursor(){free(cur->data);free(cur);}
void fetch_row(){if(cur)printf("row=%d",cur->row);}
int main(){open_cursor();close_cursor();fetch_row();return 0;}