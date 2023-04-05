from AES_TABLE import *
from MODULE import *

def main():
	
	key 	= [ 0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c ]
	message = [ 0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734 ]
	iv      = [ 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff ]

	'''
	# Input Plaintext & MODE
	message = input("PLAINTEXT : ")
	'''

	# Choose Mode
	print("\n\n")
	print("=========================================================")
	print("   [1] ECB    [2] CBC    [3] OFB    [4] CFB    [5] CTR ")
	print("=========================================================")
	mode = int(input("CHOOSE ENCRYPTION MODE : "))
	

	# Key Scheduling
	enc_rkey = Enc_Key_Schedule(key)
	dec_rkey = Dec_Key_Schedule(enc_rkey)

	# Encryption & Decryption
	if mode == 1:
		print("\n\n==> SELECTED MODE : ECB")
		ciphertext = ECB_ENC(message, enc_rkey)
		plaintext  = ECB_DEC(ciphertext, dec_rkey)
	if mode == 2:
		print("\n\n==> SELECTED MODE : CBC")
		ciphertext = CBC_ENC(message, enc_rkey, iv)
		plaintext  = CBC_DEC(ciphertext, dec_rkey, iv)
	if mode == 3:
		print("\n\n==> SELECTED MODE : OFB")
		ciphertext = OFB_ENC(message, enc_rkey, iv)
		plaintext  = OFB_DEC(ciphertext, enc_rkey, iv)
	if mode == 4:
		print("\n\n==> SELECTED MODE : CFB")
		ciphertext = CFB_ENC(message, enc_rkey, iv)
		plaintext  = CFB_DEC(ciphertext, enc_rkey, iv)
	if mode == 5:
		print("\n\n==> SELECTED MODE : CTR")
		ciphertext = CTR_ENC(message, enc_rkey)
		plaintext  = CTR_DEC(ciphertext, enc_rkey)


	# Print
	print("\n[ Message ]")
	show(message)

	print("\n[ Encrypted Message ]")
	show(ciphertext)

	print("\n[ Decrypted Message ]")
	show(plaintext)
	print("\n\n")


if __name__ == "__main__":
	
	main()
