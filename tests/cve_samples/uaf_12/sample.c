#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct{int rate;char*samples;}AudioBuf;
AudioBuf*audio=NULL;
void alloc_audio(){audio=malloc(sizeof(AudioBuf));audio->rate=44100;audio->samples=strdup("wavdata");}
void free_audio(){free(audio->samples);free(audio);}
void play_audio(){if(audio)printf("play %dHz",audio->rate);}
int main(){alloc_audio();free_audio();play_audio();return 0;}