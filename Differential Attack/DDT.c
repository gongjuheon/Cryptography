#include <stdio.h>

unsigned char sbox[16] = {1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16};
unsigned char ddt[16][16] = { 0, };

int main()
{
	for (int i = 0; i < 16; i++) {
		for(int j = 0; j < 16; j++) {
			ddt[i ^ j][sbox[i] ^ sbox[j]]++;  
		}	
	}

	for(int i = 0; i < 16; i++) {
		for(j = 0; j < 16; j++) {
			printf("%02d ", ddt);
		}
		printf("\n");
	}
}
