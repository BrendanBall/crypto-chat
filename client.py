import sys
import socket
import os
import select
from threading import Thread
from queue import Queue
from helpers import encrypt, decrypt, hash_sha256, get_nonce

# Globals
router = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router.settimeout(5)

name = ""
keys = {}
nonces = {}
# Used as temp storage for messages which a client tried to send before they had a secure connection
msg_store = []
file_store = []

# States. A full state machine could be used, but the protocol is simple enough to go without.
# These are named according to what we are waiting for.
# For example, key_ack means that we are waiting for the other
# client to acknowledge that they have the shared key
active     = [] # Clients which are completely set up

# Client A side
init_nonce = [] # Requested a nonce from receiver
auth_ack   = [] # Waiting for the auth server to send the share key etc
key_ack    = [] # Sent the shared key, encrypted with the receiver's master key
final_ack  = [] # Sent back nonce-1, waiting for confirmation that B's connection is open

# Client B side
init_key   = [] # Someone has requested a nonce. We are waiting for the shared key
nonce_ack  = [] # Sent my nonce, encrypted with the shared key

states = [active, init_nonce, auth_ack, key_ack, final_ack, init_key, nonce_ack]

def client(chat_queue, name):
	# Main logic
	while True:
		# queue.get() default is block=True, timeout=None
		# so if queue is empty this will block until not empty (just like select)
		msg = chat_queue.get()

		##############################
		# We are receiving a message #
		##############################
		if msg[0] == "socket":
			sep = msg[1].find(")")
			sender, content = msg[1][1:sep], msg[1][sep+1:].strip()

			# Control messages
			#-----------------
			if sender == "Router":
				if content.startswith("You are now known as"):
					# Confirm up my own name
					name = content.rsplit(" ", 1)[1]
					keys["Auth"] = hash_sha256(name)
				print(msg[1])
			
			elif content == "/cancel":
				cancel_connection(sender)

			# Client A
			#---------
			elif sender in init_nonce:
				# We have gotten a nonce encrypted with the other client's master key
				init_nonce.remove(sender)
				auth_ack.append(sender)
				nonces[sender] = get_nonce()
				text = "Auth: %s,%s,%s,%s" % (name, sender, nonces[sender], content)
				router.send(text.encode())
			
			elif sender == "Auth":
				# We now have a shared key from the Auth server
				plaintext = decrypt(keys["Auth"], content)
				nonce, sharedkey, receiver, receiver_block = plaintext.split(",")
				if not check_nonce(receiver, int(nonce)):
					continue
				
				auth_ack.remove(receiver)
				key_ack.append(receiver)

				keys[receiver] = sharedkey
				text = "%s: %s" % (receiver, receiver_block)
				router.send(text.encode())

			elif sender in key_ack:
				# We have gotten an encrypted nonce from the other client
				key_ack.remove(sender)
				final_ack.append(sender)

				plaintext = decrypt(keys[sender], content)
				ciphertext = "%s: %s" % (sender, encrypt(keys[sender], eval(plaintext)-1))
				router.send(ciphertext.encode())

			elif sender in final_ack:
				# Final 3 way handshake confirmation
				if content == "open":
					final_ack.remove(sender)
					active.append(sender)

					# Send any stored messages
					for msg in msg_store:
						process_message(msg, name)
					msg_store.clear()

					# Send any stored files
					for file in file_store:
						send_file(file[0], file[1])
					file_store.clear()

			# Client B
			#---------
			elif sender not in [x for state in states for x in state]:
				# Someone wants to set up a secure connection
				init_key.append(sender)
				nonces[sender] = get_nonce()
				plaintext = "%s,%s" % (sender,nonces[sender])
				send_encrypted(sender, keys["Auth"], plaintext)
			
			elif sender in init_key:
				# Someone has sent us a shared key
				init_key.remove(sender)
				nonce_ack.append(sender)
				
				plaintext = decrypt(keys["Auth"], content)
				shared_key, sender_name, nonce = plaintext.split(",")
				check_nonce(sender_name, int(nonce))

				keys[sender_name] = shared_key

				# make a new nonce to authenticate that both parties have the key
				nonces[sender] = get_nonce()
				ciphertext = "%s: %s" % (sender_name, encrypt(keys[sender_name], nonces[sender]))
				router.send(ciphertext.encode())
				
			elif sender in nonce_ack:
				# We have confirmed the connection
				nonce = int(decrypt(keys[sender], content))
				if not check_nonce(sender, nonce+1):
					continue

				nonce_ack.remove(sender)
				active.append(sender)
				
				# Do the final 3-way handshake
				text = "%s: open" % sender
				router.send(text.encode())

			elif sender in active:
				# We have a secure message
				if content.startswith("file:"):
					receive_file(sender, content[5:])
				else:
					plaintext = decrypt(keys[sender], content)
					print("(%s) %s" % (sender, plaintext))

		############################
		# We are sending a message #
		############################
		elif msg[0] == "stdin":
			process_message(msg[1], name)

def check_nonce(name, nonce):
	if not nonces[name] == nonce:
		print("%s responded with wrong nonce" % name)
		cancel_connection(name)
		print("Cancelling connection with %s" % name)
		text = "%s: /cancel" % name
		router.send(text.encode())
		return False
	return True

def cancel_connection(name):
	for state in states:
		if name in state:
			state.remove(name)
	if name in keys:
		del keys[name]
	if name in nonces:
		del nonces[name]

def process_message(msg, name):
	if msg.startswith("/name"):
		router.send(msg.encode())
	elif msg.startswith("/file"):
		fileargs = msg.split(" ")
		if fileargs[1] in active:
			send_file(fileargs[1], fileargs[2])
		else:
			file_store.append((fileargs[1], fileargs[2]))
			init_nonce.append(fileargs[1])
			text = "%s: %s" % (fileargs[1], name)
			router.send(text.encode())
	else:
		sep = msg.find(":")
		receiver, content = msg[:sep], msg[sep+1:].strip()
		if receiver in active:
			send_encrypted(receiver, keys[receiver], content)
		else:
			# Init protocol with the other client
			msg_store.append(msg) # Store the message to send it once we have a connection
			init_nonce.append(receiver)
			text = "%s: %s" % (receiver, name)
			router.send(text.encode())

def send_encrypted(receiver, key, msg):
	ciphertext = "%s: %s" % (receiver, encrypt(key, msg))
	router.send(ciphertext.encode())


def send_file(receiver, filepath):
	try:
		filebytes = b''
		with open(filepath, "rb") as readfile:
			filebytes = readfile.read()
			print("loaded file into memory")
		head, tail = os.path.split(filepath)
		filename = tail
		encrypted_filename = encrypt(keys[receiver], filename)
		ciphertext = encrypt(keys[receiver], filebytes, bytes=True)
		message = "%s:file:%s:%s" % (receiver, encrypted_filename, ciphertext)
		print(message[0:300])
		router.send(message.encode())
		print("file sent")
	except IOError as e:
		print("File not found, %s" % e)
	except MemoryError as m:
		print("Not enough memory, file too big, %s" % m)


def receive_file(sender, message):
	encrypted_filename, encrypted_filebytes = message.split(":")
	filename = decrypt(keys[sender], encrypted_filename)
	filebytes = decrypt(keys[sender], encrypted_filebytes, bytes=True)
	download_dir = "downloads"
	if not os.path.exists(download_dir):
		os.makedirs(download_dir)
	filepath = os.path.join(download_dir, filename)
	with open(filepath,"wb") as writefile:
		writefile.write(filebytes)
	print("file received")


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
	# Initial setup
	if len(sys.argv) < 3:
		print('Usage : python chat_client.py hostname port')
		sys.exit()

	host = sys.argv[1]
	port = int(sys.argv[2])

	
	# Connect to router
	try:
		router.connect((host, port))
	except socket.error:
		print("Unable to connect")
		sys.exit()

	# Queue is synchronized and completely thread safe
	# These handle stdin and the socket connection to the server
	chat_queue = Queue()
	thread_stdin = Thread(target=queue_stdin, args=(chat_queue,), daemon=True)
	thread_stdin.start()
	thread_sock = Thread(target=queue_sock_stream, args=(chat_queue, router), daemon=True)
	thread_sock.start()

	print("Connected to the router. You can start sending msgs")
	client(chat_queue, name)

