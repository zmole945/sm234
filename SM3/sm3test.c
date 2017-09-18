
#include <string.h>
#include <stdio.h>
#include "sm3.h"

static void test1(void);
static void test2(void);
static void test_msg(void);

int main( int argc, char *argv[] )
{
    test1();

    test2();

    test_msg();

    //getch();	//VS2008
}

static void test1(void)
{
    int i;
    unsigned char input[] = "abc";
    unsigned char output[32];
    int ilen = 3;

    printf("Message:\n");
    printf("%s\n",input);

    sm3(input, ilen, output);

    printf("Hash:\n   ");
    for(i=0; i<32; i++)
    {
        printf("%02x",output[i]);
        if (((i+1) % 4 ) == 0) printf(" ");
    }
    printf("\n");

}

static void test2(void)
{
    unsigned char *input = "abc";
    int ilen = 3;
    unsigned char output[32];
    int i;
    sm3_context ctx;

    printf("Message:\n");
    for(i=0; i < 16; i++)
        printf("abcd");
    printf("\n");

    sm3_starts( &ctx );
    for(i=0; i < 16; i++)
        sm3_update( &ctx, "abcd", 4 );
    sm3_finish( &ctx, output );
    memset( &ctx, 0, sizeof( sm3_context ) );

    printf("Hash:\n   ");
    for(i=0; i<32; i++)
    {
        printf("%02x",output[i]);
        if (((i+1) % 4 ) == 0) printf(" ");
    }
    printf("\n");
}

static void test_msg(void)
{
    unsigned char msg[] = "message digest";
    unsigned char output[32];
    int i;

    printf("Message:\n");
    printf("%s\n", msg);

    sm3(msg, strlen(msg), output);
    printf("Hash:\n   ");
    for(i=0; i<32; i++)
    {
        printf("%02x",output[i]);
        if (((i+1) % 4 ) == 0) printf(" ");
    }
    printf("\n");
}

