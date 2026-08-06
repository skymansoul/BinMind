#include <unistd.h>
/* read() stack overflow */
int main() { char b[64]; read(0,b,512); return 0; }