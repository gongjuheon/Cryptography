#include <stdio.h>
#include "Table.h"

unsigned long long InitialPermutation(unsigned long long plaintext)
{
    unsigned long long AIP = 0x00;
    for (int i = 0; i < 64; i++)
        AIP |= (((plaintext >> (64 - IP[i])) & 0x1) << (63 - i));
    
    return AIP;
}

unsigned long long RoundFunction(unsigned long long left, unsigned long long right, unsigned long long roundkey, int round)
{
    //Expansion
    unsigned long long AE = 0x00;
    for (int i = 0; i < 48; i++)
        AE |= (((right >> (32 - ExpansionTable[i]) & 0x1)) << (47 - i));
    
    //XOR with Key
    unsigned long long AXK = AE ^ roundkey;

    //S-Box
    unsigned long long tmp = 0x00;
    unsigned long long row = 0x00, col = 0x00;
    unsigned long long ASB = 0x00;
    
    for (int i = 0; i < 8; i++) {
        tmp = ((AXK >> (42 - 6 * i)) & 0x3f);
        row = (((tmp >> 5) << 1) | (tmp & 0x1));
        col = ((tmp & 0x1e) >> 1);
        ASB |= (SBOX[i][row][col] << (28 - 4 * i));
    }
    
    
    //D-BOX
    unsigned long long output = 0x00;
    for (int i = 0; i < 32; i++)
        output |= (((ASB >> (32 - DBOX[i])) & 0x1) << (31 - i));
    
    //XOR with Left
    unsigned long long AXL = output ^ left;

    return AXL;
}

unsigned long long KeyGeneration(unsigned long long key, unsigned long long round)
{
    unsigned long long APD = 0x00, left = 0x00, right = 0x00;
    unsigned long long roundkey[16] = { 0x00, };
    unsigned long long tmp[16] = { 0x00, };

    //Parity Drop
    for (int i = 0; i < 56; i++)
        APD |= (((key >> (64 - ParityTable[i])) & 0x1) << (55 - i));
    
    //Divide
    left = APD >> 28;
    right = APD & 0xfffffff;
    
    for (int i = 0; i < 16; i++) {
        //Shift
        left = (((left << Shifts[i]) & 0xfffffff) | (left >> (28 - Shifts[i])));
        right = (((right << Shifts[i]) & 0xfffffff) | (right >> (28 - Shifts[i])));

        //Integrate
        tmp[i] = ((left << 28) | right);
    }
    
    //Compression
    for (int i = 0; i < 48; i++)
        roundkey[round] |= (((tmp[round] >> (56 - CompressionTable[i])) & 0x1) << (47 - i));
    
    return roundkey[round];
}

unsigned long long FinalPermutation(unsigned long long ciphertext)
{
    unsigned long long AFP = 0x00;
    for (int i = 0; i < 64; i++)
        AFP |= (((ciphertext >> (64 - FP[i])) & 0x1) << (63 - i));
    
    return AFP;
}

int main()
{
    unsigned long long Plaintext = 0x00;
    unsigned long long Ciphertext = 0x00;
    unsigned long long Key = 0x00;
    unsigned long long afterIP = 0x00;
    unsigned long long left = 0x00;
    unsigned long long right = 0x00;
    unsigned long long tmp = 0x00;
    unsigned long long RoundKey[16] = { 0x00, };

    printf("====== DES ENCRYPTION =====\n");
    printf("Input Plaintext : ");
    scanf("%llx", &Plaintext);
    printf("    Input Key   : ");
    scanf("%llx", &Key);
    
    afterIP = InitialPermutation(Plaintext);

    left = (afterIP & 0xffffffff00000000) >> 32;
    right = afterIP & 0xffffffff;
    
    for (int k = 0; k < 16; k++)
        RoundKey[k] = KeyGeneration(Key, k);
    
    for (int r = 0; r < 16; r++) {
        left = RoundFunction(left, right, RoundKey[r], r);
        
        if (r != 15) {
            tmp = right;
            right = left;
            left = tmp;
        }
    }

    Ciphertext = ((left << 32) | right);
    Ciphertext = FinalPermutation(Ciphertext);
    
    printf("   Ciphertext   : %llx\n", Ciphertext);
    
    return 0;
}
