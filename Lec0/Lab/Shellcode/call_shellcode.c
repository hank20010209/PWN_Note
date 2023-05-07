#include <stdio.h>

int main(void)
{
    unsigned char shellcode_bin[] = {
        
    };
    void (*func)(void) = shellcode_bin;
    func();
}