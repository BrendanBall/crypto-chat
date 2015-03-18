from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def generate_auth_token(auth_request):
	"""
	d: decrypted text
	e: encrypted text
	kbs: with Key shared between B and this auth server
	"""
	kbs = get_client_key(auth_request[1])
	d_kbs = decrypt(kbs, auth_request[3])
	kba = generate_shared_key()
	d_kbs = "%s,%s" % (kba, d_kbs)
	e_kbs = encrypt(kbs, d_kbs)

	kas = get_client_key(auth_request[0])
	d_kas = "%s,%s,%s,%s" % (auth_request[2], kba, auth_request[1], e_kbs)
	e_kas = encrypt(kas, d_kas)
	return e_kas


def generate_shared_key():
	return Random.new().read(AES.key_size[2])


def generate_iv():
	return Random.new().read(AES.block_size)


def encrypt(key, plaintext):
	cipher = AES.new(key, AES.MODE_CFB, iv)
	ciphertext = cipher.encrypt(plaintext.encode())
	return ciphertext


def decrypt(key, ciphertext):
	cipher = AES.new(key, AES.MODE_CFB, iv)
	plaintext = cipher.decrypt(ciphertext).decode()
	return plaintext

def hash_sha256(plaintext):
	hash = SHA256.new()
	hash.update(plaintext.encode())
	return hash.digest()


def get_client_key(name):
	""" This is purely for simulation purposes """
	return hash_sha256(name)