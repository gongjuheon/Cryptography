from AES_FUNCTION import *
import random

#====================== MODIFY FUNCTIONS ======================
def show(x):
    for j in range(len(x)):
        print("{:08x} : ".format(x[j]), end='')
        if (j+1) % 4 == 0:
            print("")

def state_to_block(pt_state):
	pt_block = []
	tmp      = []

	for i in range(len(pt_state)):
		for j in range(4):
			tmp = (pt_state[i] >> (24 - 8*j)) & 0xff
			pt_block.append(tmp)

	return pt_block

def block_to_state(pt_block):
	pt_state = []

	for i in range(int(len(pt_block) / 4)):
		tmp = 0
		for j in range(4):
			tmp |= (pt_block[4*i + j] << (24 - 8*j))
		pt_state.append(tmp)

	return pt_state

def Padding(pt_block):
	pad_pt     = []
	block_size = 16
	block_num  = (len(pt_block) + block_size) // block_size

	if (len(pt_block) % 16 == 0):
		pt_block += [0 for i in range(block_size)]
		pt_block[len(pad_pt) - 1] = block_size
		
		return pt_block
	else:
		pad_num                 = block_size - (len(pt_block) % block_size)
		pad_pt                  = [0 for i in range(block_num * block_size)]
		pad_pt[0:len(pt_block)] = pt_block
		pad_pt[len(pad_pt) - 1] = pad_num

		return pad_pt

'''
def string_to_block(pt):
	pt_block = []

	for i in range(len(pt)):
		pt_block.append(ord(pt[i]))

	return pt_block
'''

def Unpadding(ct_block):
	pad_num = ct_block[-1]

	return ct_block[:-pad_num]


def Gen_Nonce():
	nonce = [0 for i in range(16)]
	for i in range(16):
		nonce[i] = random.randint(0,255)
	
	return nonce

def Counter(n):
	cnt_n = copy.deepcopy(n)
	nonce = state_to_block(cnt_n)
	nonce[15] = (nonce[15] + 1) % 256
	for i in range(15, 0, -1):
		if (nonce[i] == 0):
			c = 1
			nonce[i-1] = (nonce[i-1] + c) % 256
		else:
			c = 0
			cnt_n = block_to_state(nonce)
			return nonce
	
	cnt_n = block_to_state(nonce)
	return nonce


#================
#     MODES
#================

#========================= ECB MODE =========================
def ECB_ENC(pt, key):
	ct        = []
	pt_block  = state_to_block(pt)
	pad_pt    = Padding(pt_block)
	block_num = len(pad_pt) // 16
	pt_state  = block_to_state(pad_pt)

	for i in range(block_num):
		ct += AES_Encryption(pt_state[4*i : 4*i+4], key)

	return ct

def ECB_DEC(ct, key):
	pt        = []
	pt_state  = []
	block_num = len(ct) // 4
	
	for i in range(block_num):
		pt_state += AES_Decryption(ct[4*i : 4*i+4], key)

	pt_block = state_to_block(pt_state)
	pad_pt   = Unpadding(pt_block)
	pt       = block_to_state(pad_pt)

	return pt


#========================= CBC MODE =========================
def CBC_ENC(pt, key, IV):
	ct        = []
	tmp       = []
	tmp_iv    = copy.deepcopy(IV)
	pt_block  = state_to_block(pt)
	pad_pt    = block_to_state(Padding(pt_block))
	block_num = len(pad_pt) // 4

	for i in range(block_num):
		tmp[0 : 4] = pad_pt[4*i : 4*i+4]

		for j in range(4):
			tmp[j] ^= tmp_iv[j]

		tmp_iv   = AES_Encryption(tmp, key)
		ct      += tmp_iv

	return ct

def CBC_DEC(ct, key, IV):
	pt_state  = []
	tmp       = []
	tmp2      = []
	tmp_iv    = copy.deepcopy(IV)
	block_num = len(ct) // 4

	for i in range(block_num):
		tmp[0 : 4] = ct[4*i : 4*i+4]
		
		#pt_state = block_to_state(tmp)
		tmp2 = AES_Decryption(tmp, key)

		for j in range(4):
			tmp2[j] ^= tmp_iv[j]
		pt_state += tmp2

	pt_block = state_to_block(pt_state)
	pad_pt   = Unpadding(pt_block)
	pt       = block_to_state(pad_pt)

	return pt_state


#========================= OFB MODE =========================
def OFB_ENC(pt, key, IV):
	ct        = []
	tmp       = []
	block_num = (len(pt) + 3) // 4
	tmp_iv    = copy.deepcopy(IV)

	pt_block  = state_to_block(pt)
	block_len = len(pt_block)

	for i in range(block_num):
		tmp_iv     = AES_Encryption(tmp_iv, key)
		tmp[0 : 4] = pt[4*i : 4*i+4]

		for j in range(4):
			tmp[j] ^= tmp_iv[j]
		ct += tmp

	ct_block = state_to_block(ct)
	ct_block = ct_block[:block_len]
	ct       = block_to_state(ct_block)
	
	return ct

def OFB_DEC(ct, key, IV):
	pt_state  = []
	tmp       = []
	block_num = (len(ct) + 3) // 4
	tmp_iv    = copy.deepcopy(IV)

	ct_block  = state_to_block(ct)
	block_len = len(ct_block)

	for i in range(block_num):
		tmp_iv     = AES_Encryption(tmp_iv, key)
		tmp[0 : 4] = ct[4*i : 4*i+4]

		for j in range(4):
			tmp[j] ^= tmp_iv[j]
		pt_state += tmp

	pt_block = state_to_block(pt_state)
	pt_block = pt_block[:block_len]
	pt_state = block_to_state(pt_block)
	
	return pt_state


#========================= CFB MODE =========================
def CFB_ENC(pt, key, IV):
	ct        = []
	tmp       = []
	block_num = (len(pt) + 3) // 4
	tmp_iv    = copy.deepcopy(IV)

	pt_block  = state_to_block(pt)
	block_len = len(pt_block)

	for i in range(block_num):
		tmp_iv     = AES_Encryption(tmp_iv, key)
		tmp[0 : 4] = pt[4*i : 4*i+4]

		for j in range(4):
			tmp_iv[j] ^= tmp[j]
		ct += tmp_iv

	ct_block = state_to_block(ct)
	ct_block = ct_block[:block_len]
	ct       = block_to_state(ct_block)
	
	return ct

def CFB_DEC(ct, key, IV):
	pt_state  = []
	tmp       = []
	tmp2      = []
	tmp_iv    = copy.deepcopy(IV)
	block_num = len(ct) // 4

	ct_block  = state_to_block(ct)
	block_len = len(ct_block)

	for i in range(block_num):
		tmp_iv     = AES_Encryption(tmp_iv, key)
		tmp[0 : 4] = ct[4*i : 4*i+4]

		for j in range(4):
			tmp_iv[j] ^= tmp[j]
		pt_state += tmp_iv

	pt_block = state_to_block(pt_state)
	pt_block = pt_block[:block_len]
	pt_state = block_to_state(pt_block)

	return pt_state


#========================= CTR MODE =========================
def CTR_ENC(pt, key):
	ct        = []
	tmp       = []
	tmp2      = [] 
	block_num = (len(pt) + 3) // 4
	nonce     = block_to_state(Gen_Nonce())
	tmp_nonce = copy.deepcopy(nonce)

	pt_block  = state_to_block(pt)
	block_len = len(pt_block)

	for i in range(block_num):
		tmp2 = AES_Encryption(nonce, key)
		tmp[0 : 4] = pt[4*i : 4*i+4]

		for j in range(4):
			tmp[j] ^= tmp2[j]
		nonce = Counter(nonce)
		ct += tmp
	
	ct += tmp_nonce
	
	return ct

def CTR_DEC(ct, key):
	pt        = []
	tmp       = []
	tmp2      = []
	nonce     = ct[len(ct)-4 : ]
	ct        = ct[:len(ct)-4]
	block_num = (len(ct) + 3) // 4

	for i in range(block_num):
		tmp2 = AES_Encryption(nonce, key)
		tmp[0 : 4] = ct[4*i : 4*i+4]

		for j in range(4):
			tmp[j] ^= tmp2[j]
		nonce = Counter(nonce)
		pt += tmp
	
	return pt