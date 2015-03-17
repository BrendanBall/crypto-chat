import sys
import socket
import select
from threading import Thread
from queue import Queue
from Crypto import Random
from Crypto.Cipher import AES


# initialization vector
iv = b'g\x9e\xecI\x0f\x9b\x81*,\x94\xaa)\x96x$q'


def auth_server():
	if len(sys.argv) < 3:
		print('Usage : python chat_client.py hostname port')
		sys.exit()

	host = sys.argv[1]
	port = int(sys.argv[2])

	router_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	router_socket.settimeout(2)

	# connect to router
	try:
		router_socket.connect((host, port))
		router_socket.send("/name auth_server".encode())
	except socket.error:
		print("Unable to connect")
		sys.exit()

	print("Connected to the router. You can start sending messages")

	# queue is synchronized and completely thread safe
	chat_queue = Queue()
	thread_stdin = Thread(target=queue_stdin, args=(chat_queue,), daemon=True)
	thread_stdin.start()
	thread_sock = Thread(target=queue_sock_stream, args=(chat_queue, router_socket), daemon=True)
	thread_sock.start()

	while True:
		# queue.get() default is block=True, timeout=None
		# so if queue is empty this will block until not empty (just like select)
		message = chat_queue.get()
		if message[0] == "socket":
			message = split_msg(message[1])
			print(message)
			if not message[0] == "Router":
				print("authenticate")
				auth_request = message[0].split(":")
				auth_token = generate_auth_token(auth_request)
				router_socket.send("%s:%s" % (message[0], auth_token).encode())

		elif message[0] == "stdin":
			router_socket.send(message[1].encode())


def queue_stdin(q):
	for line in sys.stdin:
		q.put(("stdin", line.strip()))


def queue_sock_stream(q, s):
	while True:
		# still using select for sockets because
		# it is merely an interface to a system call so better to use for sockets
		ready_to_read, ready_to_write, in_error = select.select([s], [], [])
		for sock in ready_to_read:
			data = sock.recv(4096).decode()
			if not data:
				sock.close()
				q.put(("socket", "Server has closed the connection"))
				sys.exit()
			else:
				q.put(("socket", data))


def generate_auth_token(auth_request):
	"""
	d: decrypted text
	e: encrypted text
	kbs: with Key shared between B and this auth server
	"""
	kbs = get_client_key(auth_request[1])
	d_kbs = decrypt(kbs, auth_request[3])
	kba = generate_shared_key()
	d_kbs = "%s:%s" % (kba, d_kbs)
	e_kbs = encrypt(kbs, d_kbs)

	kas = get_client_key(auth_request[0])
	d_kas = "%s:%s:%s%s" % (auth_request[2], kba, auth_request[1], e_kbs)
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


def get_client_key(name):
	return name.encode()


def split_msg(msg):
	sep = msg.find(")")
	return (msg[1:sep].strip(), msg[sep+1:].strip())


if __name__ == "__main__":
	try:
		auth_server()
	except KeyboardInterrupt:
		pass

