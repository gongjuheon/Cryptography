from AES_TABLE import *
from MODULE import *
import copy

def Enc_Key_Schedule(key):
	
	enc_rkey = [key]

	x0, x1, x2, x3 = enc_rkey[0][0], enc_rkey[0][1], enc_rkey[0][2], enc_rkey[0][3]

	for i in range(1, 11):
		x0 = (x0 & 0xff000000) ^ (SBOX[(x3 & 0x00ff0000) >> 16] << 24) ^ Rcon[i-1] ^ \
			 (x0 & 0x00ff0000) ^ (SBOX[(x3 & 0x0000ff00) >> 8] << 16) ^ (x0 & 0x0000ff00) ^ \
			 (SBOX[(x3 & 0x000000ff)] << 8) ^ (x0 & 0x000000ff) ^ SBOX[(x3 & 0xff000000) >> 24]
		
		x1 = (x0 & 0xff000000) ^ (x1 & 0xff000000) ^ (x0 & 0x00ff0000) ^ (x1 & 0x00ff0000) ^ \
				 (x0 & 0x0000ff00) ^ (x1 & 0x0000ff00) ^ (x0 & 0x000000ff) ^ (x1 & 0x000000ff)

		x2 = (x1 & 0xff000000) ^ (x2 & 0xff000000) ^ (x1 & 0x00ff0000) ^ (x2 & 0x00ff0000) ^ \
				 (x1 & 0x0000ff00) ^ (x2 & 0x0000ff00) ^ (x1 & 0x000000ff) ^ (x2 & 0x000000ff)

		x3 = (x2 & 0xff000000) ^ (x3 & 0xff000000) ^ (x2 & 0x00ff0000) ^ (x3 & 0x00ff0000) ^ \
			 	 (x2 & 0x0000ff00) ^ (x3 & 0x0000ff00) ^ (x2 & 0x000000ff) ^ (x3 & 0x000000ff)

		enc_rkey += [[x0, x1, x2, x3]]

	return enc_rkey


def Dec_Key_Schedule(rkey):

	dec_rkey = copy.deepcopy(rkey)
	dec_rkey = list(reversed(dec_rkey))

	for i in range(1, 10):
		x0 = Td0[Te1[(dec_rkey[i][0] >> 24)] & 0xff] ^ Td1[Te1[(dec_rkey[i][0] >> 16) & 0xff] & 0xff] ^ \
				 Td2[Te1[(dec_rkey[i][0] >>  8) & 0xff] & 0xff] ^ Td3[Te1[(dec_rkey[i][0]) & 0xff] & 0xff]
		x1 = Td0[Te1[(dec_rkey[i][1] >> 24)] & 0xff] ^ Td1[Te1[(dec_rkey[i][1] >> 16) & 0xff] & 0xff] ^ \
				 Td2[Te1[(dec_rkey[i][1] >>  8) & 0xff] & 0xff] ^ Td3[Te1[(dec_rkey[i][1]) & 0xff] & 0xff]
		x2 = Td0[Te1[(dec_rkey[i][2] >> 24)] & 0xff] ^ Td1[Te1[(dec_rkey[i][2] >> 16) & 0xff] & 0xff] ^ \
				 Td2[Te1[(dec_rkey[i][2] >>  8) & 0xff] & 0xff] ^ Td3[Te1[(dec_rkey[i][2]) & 0xff] & 0xff]
		x3 = Td0[Te1[(dec_rkey[i][3] >> 24)] & 0xff] ^ Td1[Te1[(dec_rkey[i][3] >> 16) & 0xff] & 0xff] ^ \
				 Td2[Te1[(dec_rkey[i][3] >>  8) & 0xff] & 0xff] ^ Td3[Te1[(dec_rkey[i][3]) & 0xff] & 0xff]

		dec_rkey[i][0] = x0
		dec_rkey[i][1] = x1
		dec_rkey[i][2] = x2
		dec_rkey[i][3] = x3

	return dec_rkey


def AES_Encryption(message, rkey):

	tmp = [0, 0, 0, 0]

	message[0] ^= rkey[0][0]
	message[1] ^= rkey[0][1]
	message[2] ^= rkey[0][2]
	message[3] ^= rkey[0][3]

	for i in range(1,10):

		tmp[0] = message[0]
		tmp[1] = message[1]
		tmp[2] = message[2]
		tmp[3] = message[3]
	
		message[0] = Te0[(tmp[0] >> 24)] ^ Te1[(tmp[1] >> 16) & 0xff] ^ Te2[(tmp[2] >> 8) & 0xff] ^ Te3[tmp[3] & 0xff] ^ rkey[i][0]
		message[1] = Te0[(tmp[1] >> 24)] ^ Te1[(tmp[2] >> 16) & 0xff] ^ Te2[(tmp[3] >> 8) & 0xff] ^ Te3[tmp[0] & 0xff] ^ rkey[i][1]
		message[2] = Te0[(tmp[2] >> 24)] ^ Te1[(tmp[3] >> 16) & 0xff] ^ Te2[(tmp[0] >> 8) & 0xff] ^ Te3[tmp[1] & 0xff] ^ rkey[i][2]
		message[3] = Te0[(tmp[3] >> 24)] ^ Te1[(tmp[0] >> 16) & 0xff] ^ Te2[(tmp[1] >> 8) & 0xff] ^ Te3[tmp[2] & 0xff] ^ rkey[i][3]

	tmp[0] = message[0]
	tmp[1] = message[1]
	tmp[2] = message[2]
	tmp[3] = message[3]
	
	message[0] = ((SBOX[tmp[0] >> 24]) << 24) ^ (SBOX[(tmp[1] >> 16) & 0xff] << 16) ^ (SBOX[(tmp[2] >> 8) & 0xff] << 8) ^ (SBOX[tmp[3] & 0xff]) ^ rkey[10][0]
	message[1] = ((SBOX[tmp[1] >> 24]) << 24) ^ (SBOX[(tmp[2] >> 16) & 0xff] << 16) ^ (SBOX[(tmp[3] >> 8) & 0xff] << 8) ^ (SBOX[tmp[0] & 0xff]) ^ rkey[10][1]
	message[2] = ((SBOX[tmp[2] >> 24]) << 24) ^ (SBOX[(tmp[3] >> 16) & 0xff] << 16) ^ (SBOX[(tmp[0] >> 8) & 0xff] << 8) ^ (SBOX[tmp[1] & 0xff]) ^ rkey[10][2]
	message[3] = ((SBOX[tmp[3] >> 24]) << 24) ^ (SBOX[(tmp[0] >> 16) & 0xff] << 16) ^ (SBOX[(tmp[1] >> 8) & 0xff] << 8) ^ (SBOX[tmp[2] & 0xff]) ^ rkey[10][3]
		
	return message


def AES_Decryption(ciphertext, rkey):

	tmp = [0, 0, 0, 0]

	ciphertext[0] ^= rkey[0][0]	
	ciphertext[1] ^= rkey[0][1]
	ciphertext[2] ^= rkey[0][2]
	ciphertext[3] ^= rkey[0][3]

	for i in range(1, 10):

		tmp[0] = ciphertext[0]
		tmp[1] = ciphertext[1]
		tmp[2] = ciphertext[2]
		tmp[3] = ciphertext[3]
 
		ciphertext[0] = Td0[(tmp[0] >> 24)] ^ Td1[(tmp[3] >> 16) & 0xff] ^ Td2[(tmp[2] >> 8) & 0xff] ^ Td3[tmp[1] & 0xff] ^ rkey[i][0]	
		ciphertext[1] = Td0[(tmp[1] >> 24)] ^ Td1[(tmp[0] >> 16) & 0xff] ^ Td2[(tmp[3] >> 8) & 0xff] ^ Td3[tmp[2] & 0xff] ^ rkey[i][1]
		ciphertext[2] = Td0[(tmp[2] >> 24)] ^ Td1[(tmp[1] >> 16) & 0xff] ^ Td2[(tmp[0] >> 8) & 0xff] ^ Td3[tmp[3] & 0xff] ^ rkey[i][2]
		ciphertext[3] = Td0[(tmp[3] >> 24)] ^ Td1[(tmp[2] >> 16) & 0xff] ^ Td2[(tmp[1] >> 8) & 0xff] ^ Td3[tmp[0] & 0xff] ^ rkey[i][3]

	tmp[0] = ciphertext[0]
	tmp[1] = ciphertext[1]
	tmp[2] = ciphertext[2]
	tmp[3] = ciphertext[3]

	ciphertext[0] = ((INV_SBOX[tmp[0] >> 24]) << 24) ^ (INV_SBOX[(tmp[3] >> 16) & 0xff] << 16) ^ (INV_SBOX[(tmp[2] >> 8) & 0xff] << 8) ^ (INV_SBOX[tmp[1] & 0xff]) ^ rkey[10][0]
	ciphertext[1] = ((INV_SBOX[tmp[1] >> 24]) << 24) ^ (INV_SBOX[(tmp[0] >> 16) & 0xff] << 16) ^ (INV_SBOX[(tmp[3] >> 8) & 0xff] << 8) ^ (INV_SBOX[tmp[2] & 0xff]) ^ rkey[10][1]
	ciphertext[2] = ((INV_SBOX[tmp[2] >> 24]) << 24) ^ (INV_SBOX[(tmp[1] >> 16) & 0xff] << 16) ^ (INV_SBOX[(tmp[0] >> 8) & 0xff] << 8) ^ (INV_SBOX[tmp[3] & 0xff]) ^ rkey[10][2]
	ciphertext[3] = ((INV_SBOX[tmp[3] >> 24]) << 24) ^ (INV_SBOX[(tmp[2] >> 16) & 0xff] << 16) ^ (INV_SBOX[(tmp[1] >> 8) & 0xff] << 8) ^ (INV_SBOX[tmp[0] & 0xff]) ^ rkey[10][3]

	return ciphertext