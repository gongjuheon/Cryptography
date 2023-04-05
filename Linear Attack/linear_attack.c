/* Linear Attack

- probability : -1/128
- bias        : -1/32
- 0xD -> (SBOX) -> 0x2 -> (PERM) -> 0x4 -> (SBOX) -> 0x4 -> (PERM) -> 0x8 -> (SBOX) -> 0xF

*/

#define CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>

uint8_t static SBOX[16]    = { 0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2 };
uint8_t static InvSBOX[16] = { 0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA };
uint8_t static InvPT[32]   = { 6, 9, 12, 3, 2, 5, 8, 31, 30, 1, 4, 27, 26, 29, 0, 23, 22, 25, 28, 19, 18, 21, 24, 15, 14, 17, 20, 11, 10, 13, 16, 7 };

uint32_t InversePermutation(uint32_t AXK)
{
	uint32_t APT = 0x00;

	for (int k = 0; k < 32; k++)
		APT |= ((AXK >> k) & 0x1) << (InvPT[31 - k]);

	return APT;
}

uint32_t InverseSBOX(uint32_t AXK)
{
	uint32_t ASB = 0x00;
	uint32_t tmp = 0x00;

	for (int k = 0; k < 8; k++) {
		tmp = (AXK >> (28 - k * 4)) & 0xf;
		ASB |= InvSBOX[tmp] << (28 - k * 4); 
	}

	return ASB;
}

int main()
{
	FILE *PT = NULL;
	FILE *CT = NULL;
	int ciphertext[4096] = { 0, };
	int plaintext[4096]  = { 0, };
	int count[0xffff]      = { 0, };
	uint32_t AXK = 0x00;
	uint32_t ASB = 0x00;
	uint32_t APT = 0x00;
	char x5= 0x00, x6 = 0x00;
	char u25 = 0x00, u26 = 0x00, u27 = 0x00, u28 = 0x00;
	char check = 0x00;
	int max = 0;
	uint16_t maxkey = 0x00;

	PT = fopen("Plaintext1.txt", "r");
	CT = fopen("Ciphertext1.txt", "r");

	for (int i = 0; i < 4096; i++) {
		fscanf(PT, "%x", &plaintext[i]);
		fscanf(CT, "%x", &ciphertext[i]);

		x5 = (plaintext[i] >> 27) * 0x1;
		x6 = (plaintext[i] >> 26) * 0x1;

		for (int j = 0; j < 0xffff; j++) {
			AXK = ciphertext[i] ^ j;
			ASB = InverseSBOX(AXK);
			AXK = ASB ^ j;
			APT = InversePermutation(AXK);

			u25 = (APT >> 7) * 0x1;
			u26 = (APT >> 6) * 0x1;
			u27 = (APT >> 5) * 0x1;
			u28 = (APT >> 4) * 0x1;

			check = x5 ^ x6 ^ u25 ^ u26 ^ u27 ^ u28;

			if (check == 0)
				count[j]++;
		}
	}

	fclose(PT);
	fclose(CT);

	for (int i = 0; i < 0xffff; i++) {
		if (abs(count[i] - 2048) > (4096 / 32)) {
			printf("Count : %d, Key : %04x\n", abs(count[i] - 2048), i);
		}
	}

	return 0;
}
