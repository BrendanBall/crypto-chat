from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64

iv = b'sixteen byte key'

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


def generate_auth_token_simple(auth_request):
	kbs = get_client_key(auth_request[1])
	kas = get_client_key(auth_request[0])
	print("client key for kbs: %s" % kbs)
	kba = generate_shared_key()
	print("key for kba: %s" % kba)

	d_kbs = "%s,%s" % (kba, auth_request[0])
	e_kbs = encrypt(kbs, d_kbs)
	d_kas = "%s,%s,%s,%s" % (auth_request[2], kba, auth_request[1], e_kbs)
	#print("unencrypted auth_token: ", d_kas)
	e_kas = encrypt(kas, d_kas)
	#print(e_kas)
	print("encrypt decrypt: ",decrypt(kas, e_kas))

	return e_kas

def generate_shared_key():
	return base64.b64encode(Random.new().read(AES.key_size[2]))


def generate_iv():
	return Random.new().read(AES.block_size)


def encrypt(key, plaintext):
	cipher = AES.new(base64.b64decode(key), AES.MODE_CFB, iv)
	ciphertext = cipher.encrypt(plaintext.encode())
	return base64.b64encode(ciphertext)


def decrypt(key, ciphertext):
	with open("testfile.log", "a") as outfile:
		print("decrypted before decoding: key:\n%s\nciphertext:\n %s\n" % (key,ciphertext), file=outfile)
	cipher = AES.new(base64.b64decode(key), AES.MODE_CFB, iv)
	plaintext = cipher.decrypt(base64.b64decode(ciphertext))
	
	plaintext = plaintext.decode()
	print(plaintext)
	return plaintext

def hash_sha256(plaintext):
	hash = SHA256.new()
	hash.update(plaintext.encode())
	return base64.b64encode(hash.digest())


def get_client_key(name):
	""" This is purely for simulation purposes """
	hash = hash_sha256(name)
	print(type(hash))
	return hash
