import sys
import socket
import select
from threading import Thread
from queue import Queue
from auth_lib import encrypt, decrypt, hash_sha256

# Globals
name = ""
keys = {}
nonces = {}

# States. A full state machine could be used, but the protocol is simple enough to go without.
# These are named according to what we are waiting for.
# For example, key_ack means that we are waiting for the other
# client to acknowledge that they have the shared key
active     = [] # Clients which are completely set up

# Client A side
init_nonce = [] # Requested a nonce from receiver
auth_ack   = [] # Waiting for the auth server to send the share key etc
key_ack    = [] # Sent the shared key, encrypted with the receiver's master key

# Client B side
init_key   = [] # Someone has requested a nonce. We are waiting for the shared key
nonce_ack  = [] # Sent my nonce, encrypted with the shared key


def client(chat_queue):
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

			if sender == "Router":
				if content.startswith("You are now known as"):
					# Confirm up my own name
					name = content.rsplit(" ", 1)[1]
					keys["Auth"] = hash_sha256(name)
				print(msg[1])

			elif sender == "Auth":
				# We now have a shared key
				plaintext = decrypt(keys["Auth"], content)
				nonce, sharedkey, receiver, receiver_block = plaintext.split(",")
				# TODO: check nonce
				
				auth_ack.remove(receiver)
				key_ack.append(receiver)

				keys[receiver] = sharedkey
				text = "%s: %s" % (receiver, receiver_block)
				router.send(ciphertext.encode())


			# Client B
			#---------
			elif sender not in (set(init_nonce)|set(auth_ack)|set(key_ack)|set(nonce_ack)|set(active)):
				# Someone wants to set up a secure connection
				init_key.append(sender)
				nonces[sender] = 1 #TODO: make nonce
				plaintext = "%s,%s" % (sender, nonces[sender])
				send_encrypted(sender, keys["Auth"], plaintext)
			
			elif sender in init_key:
				# Someone has sent us a shared key
				init_key.remove(sender)
				nonce_ack.append(sender)

				plaintext = decrypt(keys["Auth"], content)
				shared_key, sender_name, nonce = plaintext.split(",")
				# TODO: check nonce
				keys[sender_name] = shared_key

				new_nonce = 2
				ciphertext = "%s: %s" % (sender_name, encrypt(keys[sender_name], new_nonce))
				router.send(ciphertext.encode())
			
			elif sender in nonce_ack:
				# We have confirmed the connection
				# TODO: check nonce
				nonce_ack.remove(sender)
				active.append(sender)
			
			elif sender in active:
				# We have a secure message
				plaintext = decrypt(keys[sender], content)
				print(plaintext)

			# Client A
			#---------
			elif sender in init_nonce:
				# We have gotten a nonce encrypted with the other client's master key
				init_nonce.remove(sender)
				auth_ack.append(sender)
				nonces[sender] = 1 # TODO
				text = "Auth: %s,%s,%s,%s" % (name, sender, nonces[sender], content)
				router.send(text.encode())
			
			elif sender in key_ack:
				# We have gotten an encrypted nonce from the other client
				key_ack.remove(sender)
				active.append(sender)

				plaintext = decrypt(keys[sender], content)
				ciphertext = encrypt(keys[sender], eval(plaintext)-1)
				router.send(ciphertext.encode())
				


					
		############################
		# We are sending a message #
		############################
		elif msg[0] == "stdin":
			if msg[1].startswith("/name"):
				router.send(msg[1].encode())
			else:
				sep = msg[1].find(":")
				receiver, content = msg[1][:sep], msg[1][sep+1:].strip()
				
				if receiver in keys:
					send_encrypted(receiver, keys[receiver], content)
				else:
					# Init protocol with the other client
					init_nonce.append(receiver)
					text = "%s: %s" % (receiver, name)
					router.send(text.encode())


def send_encrypted(receiver, key, msg):
	ciphertext = "%s: %s" % (receiver, encrypt(key, msg))
	router.send(ciphertext.encode())

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

	router = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	router.settimeout(5)
	
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
	client(chat_queue)

