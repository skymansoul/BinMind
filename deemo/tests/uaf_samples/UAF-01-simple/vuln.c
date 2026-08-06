void f(){char*p=malloc(64);free(p);p[0]=0;}
int main(){f();return 0;}