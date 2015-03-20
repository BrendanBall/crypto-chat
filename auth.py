import sys
import socket
import select
from threading import Thread
from queue import Queue
from helpers import *


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
		router_socket.send("/name Auth".encode())
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
			print(message[1])
			message = split_msg(message[1])
			if not message[0] == "Router":
				auth_request = message[1].split(",")
				auth_token = generate_auth_token(auth_request)
				msg_send = "%s:%s" % (message[0], auth_token)
				router_socket.send(msg_send.encode())

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


def split_msg(msg):
	sep = msg.find(")")
	return (msg[1:sep].strip(), msg[sep+1:].strip())


if __name__ == "__main__":
	try:
		auth_server()
	except KeyboardInterrupt:
		pass

