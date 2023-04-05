#define CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main()
{
    FILE *pA, *pB, *cA, *cB;
    uint32_t random = 0;
    uint32_t plain_a = 0x00, plain_b = 0x00;
	uint32_t cipher_a = 0x00, cipher_b = 0x00;
    uint32_t a = 0x00;
    
    //Write Plaintext
    pA = fopen("Plaintext_A.txt", "w");
    pB = fopen("Plaintext_B.txt", "w");
    srand((unsigned)time(NULL));
    
    for (int i = 0; i < 0x7ff; i++) {
        random = rand() % 0xffffffff;
        plain_a = random;
        a = !((random >> 24) & 0x1);
        plain_b = (plain_a & 0xfeffffff) | (a << 24);
        
        fprintf(pA, "%x\n", plain_a);
        fprintf(pB, "%x\n", plain_b);
    }
    
    fclose(pA);
    fclose(pB);

    return 0;
}
