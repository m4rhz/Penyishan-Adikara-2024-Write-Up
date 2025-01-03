#include <stdio.h>
#include <stdlib.h>

// gcc -fno-stack-protector -no-pie vuln.c

void init_buffer()
{
    setvbuf(stdin , NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main()
{
    init_buffer();
    
    // START HERE
    size_t overflow_me = 0; 
    char buf[0x40];

    puts("< This is simple buffer overflow vulnerability.");
    puts("< You have to change value of `overflow_me` variable with this bug.");
    puts("< On `Buffer Overflow 2` you have to change value to 0xdeadbeef.");
    printf("< First, `overflow_me` is set to 0x%lx.", overflow_me);
    puts("< Now, time is yours!");
    printf("> ");

    gets(buf);

    printf("< %s\n", buf);
    printf("< Now `overflow_me` is 0x%lx\n", overflow_me);

    if (overflow_me > 0)
    {
        printf("< Nice work! `overflow_me` has changed!\n");
        if (overflow_me == 0xdeadbeef) {
            system("cat flag-2.txt");
        } else {
            system("cat flag-1.txt");
        }
    }
    return 0;
}