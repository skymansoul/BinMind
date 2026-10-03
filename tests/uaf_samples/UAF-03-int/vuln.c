void f(){int*x=malloc(16);free(x);*x=42;}
int main(){f();return 0;}