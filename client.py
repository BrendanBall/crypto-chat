import sys
import socket
import select
from threading import Thread
from queue import Queue
from auth_lib import encrypt, decrypt, hash_sha256

def client():
	if len(sys.argv) < 3:
		print('Usage : python chat_client.py hostname port')
		sys.exit()

	host = sys.argv[1]
	port = int(sys.argv[2])

	router_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	router_socket.settimeout(2)

	name = ""
	keyring = {"Auth": ""}
	nonces = {}
	waiting_key_conf_out = [] # Me setting up with someone
	waiting_key_conf_in = []  # Someone setting up with me
	active_channels = []

	# connect to router
	try:
		router_socket.connect((host, port))
	except socket.error:
		print("Unable to connect")
		sys.exit()

	print("Connected to the router. You can start sending msgs")

	# queue is synchronized and completely thread safe
	chat_queue = Queue()
	thread_stdin = Thread(target=queue_stdin, args=(chat_queue,), daemon=True)
	thread_stdin.start()
	thread_sock = Thread(target=queue_sock_stream, args=(chat_queue, router_socket), daemon=True)
	thread_sock.start()

	def send_encrypted(receiver_name, msg):
		if receiver_name in keyring:
			router_socket.send(encrypt(keyring[receiver_name], msg).encode())
		else:
			# Needham–Schroeder protocol (outbound)
			nonce = ""
			content = "Auth: %s,%s,%s" % (name, receiver_name, nonce)
			router_socket.send(content.encode())

	while True:
		# queue.get() default is block=True, timeout=None
		# so if queue is empty this will block until not empty (just like select)
		msg = chat_queue.get()

		# We are receiving a message
		if msg[0] == "socket":
			sep = msg[1].find(")")
			sender, content = msg[1][1:sep], msg[1][sep+1:].strip()
			if sender == "Router":
				if content.startswith("You are now known as"):
					name = content.rsplit(" ", 1)[1]
					keyring["Auth"] = hash_sha256(name)
				print(msg[1])
			elif sender == "Auth":
				# Needham–Schroeder protocol (inbound)
				plaintext = decrypt(keyring[sender], content)
				nonce, sharedkey, receiver, receiver_block = plaintext.split(",")
				# TODO: check nonce
				keyring[receiver] = sharedkey
				router_socket.send(receiver_block)
				waiting_key_confirmation.append(receiver)
			else:
				if sender in waiting_key_conf_in:
					# We have successfully received a connection
					# TODO: check nonce
					waiting_key_conf_in.remove(sender)
					active_channels.append(sender)
				if sender in waiting_key_conf_out:
					# We have successfully initiated a connection
					waiting_key_conf_out.remove(sender)
					sender_nonce = eval(decrypt(keyring[sender], content))
					send_encrypted(sender, encrypt(keyring[sender], sender_nonce-1))
					active_channels.append(sender)
				elif sender in active_channels:
					print(keyring[sender], decrypt(msg[1]))
				else:
					# Someone else must be trying to set up a connection with us
					plaintext = decrypt(keyring["Auth"], content)
					shared_key, sender_name = plaintext.split(",")
					keyring[sender_name] = shared_key
					nonce = ""
					send_encrypted(sender_name, nonce)
					waiting_conf_in.append(sender)
					
		# We are sending a message
		elif msg[0] == "stdin":
			if msg[1].startswith("/name"):
				router_socket.send(msg[1].encode())
			else:
				sep = msg[1].find(":")
				receiver, content = msg[1][:sep], msg[1][sep+1:].strip()
				send_encrypted(receiver, content)

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

if __name__ == "__main__":
	client()

