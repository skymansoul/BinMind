void f(){char*b=malloc(32);char*a=b;free(b);a[0]=0;}
int main(){f();return 0;}