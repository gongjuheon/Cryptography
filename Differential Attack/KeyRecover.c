#define CRT_SECURE_NO_WARNINGS
  
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

uint8_t static SBOX[16] = { 1, 10, 4, 12, 6, 15, 3, 9, 2, 13, 11, 7, 5, 0, 8, 14 };
uint8_t static InvPT[32] = { 6, 9, 12, 3, 2, 5, 8, 31, 30, 1, 4, 27, 26, 29, 0, 23, 22, 25, 28, 19, 18, 21, 24, 15, 14, 17, 20, 11, 10, 13, 16, 7 };
uint8_t static InvSBOX[16] = { 13, 0, 8, 6, 2, 12, 4, 11, 14, 7, 1, 10, 3, 9, 15, 5 };
uint8_t static PT[32] = { 14, 9, 4, 3, 10, 5, 0, 31, 6, 1,
    28, 27, 2, 29, 24, 23, 30, 25, 20, 19,
    26, 21, 16, 15, 22, 17, 12, 11, 18, 13, 8, 7 };

uint32_t InversePermutation(uint32_t AX)
{	
	uint32_t AIP = 0x00;

	for (int k = 0; k < 32; k++)
		AIP |= ((AX >> k) & 0x1) << (InvPT[31 - k]);

	return AIP;
}	

uint32_t InverseSBOX(uint32_t APT)
{
	uint32_t ASB = 0x00;
	uint32_t tmp = 0x00;

	for (int k = 0; k < 8; k++) {
		tmp = (APT >> (28 - k * 4)) & 0xf;
		ASB |= InvSBOX[tmp] << (28 - k * 4); 
	}

	return ASB;
}

int main()
{
    FILE *cA = NULL, *cB = NULL;
	uint32_t ciphertext_A = 0x00, ciphertext_B = 0x00;
	uint32_t maxkey = 0x00;
	uint32_t AX_A = 0x00, APT_A = 0x00, ASB_A = 0x00;
	uint32_t AX_B = 0x00, APT_B = 0x00, ASB_B = 0x00;
	uint16_t check = 0x00;
	int cipher_A[2048] = { 0x00, };
	int cipher_B[2048] = { 0x00, };
	int count[0xffff] = { 0, };         //배열을 사용하지 않도록
	int max = 0;

    cA = fopen("Ciphertext_A.txt", "r");
    cB = fopen("Ciphertext_B.txt", "r");

	for (int i = 0; i < 2048; i++) {
		fscanf(cA, "%x", &cipher_A[i]);
		fscanf(cB, "%x", &cipher_B[i]);

		for (int j = 0; j < 0xffff; j++) {
			APT_A = InversePermutation(cipher_A[i]);
			APT_B = InversePermutation(cipher_B[i]);

			ASB_A = InverseSBOX(APT_A ^ j);
			ASB_B = InverseSBOX(APT_B ^ j);

			check = (ASB_A ^ ASB_B) & 0xffff;
			
			if (check == 0x1842)
				count[j]++;
		}
	}

	fclose(cA);
    fclose(cB);

    for (int i = 0; i < 0xffff; i++) {  //상위 5개를 출력하게끔
		if (count[i] > max) {
			max = count[i];
			maxkey = i;
		}
	}

	printf("MAX : %d\n", max);
	printf("KEY : %x\n", maxkey);

	return 0;
}
