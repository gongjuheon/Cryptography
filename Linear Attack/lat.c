#include <stdio.h>
#include <stdint.h>

int validBit(int num, int mask)
{
	int sum = 0;
	int tmp = 0, tmp1 = 0;

	for (int i = 0; i < 4; i++) {

		tmp = (mask >> i) & 1;
		tmp1 = (num >> i) & 1;

		if (tmp == 1)
			sum ^= tmp & tmp1;
	}

	return sum;
}

int main()
{
	uint8_t static SBOX[16] = { 0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2 };
	uint8_t LAT[16][16] = { 0, };


	for (int a = 0; a < 16; a++)
        for (int b = 0; b < 16; b++)
            for (int x = 0; x < 16; x++)
                if ((validBit(a & x, a) ^ validBit(b & SBOX[x], b)) == 0)
					LAT[a][b] += 1;


	for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++)
			printf("%02d ", LAT[i][j]);

		printf("\n");
	}


	return 0;
}
