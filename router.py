import socket
import select
from helpers import socket_buffer_size

sockets = [] 
port = 8001
clients = {}


def router():
	router_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	router_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	router_socket.bind(("", port))
	router_socket.listen(10)
	
	sockets.append(router_socket)
	print("Server started on port %s" % port)

	while True:
		# check if there are any changes
		ready_to_read, ready_to_write, in_error = select.select(sockets, [], [])

		for sock in ready_to_read:
			if sock == router_socket: 
				new_sock, addr = router_socket.accept()
				sockets.append(new_sock)
				print("Client (%s, %s) connected" % addr)
			else:
				try:
					# get messages from the client
					data = sock.recv(socket_buffer_size).decode()
					if data:
						# there is something in the socket
						if data.startswith("/name"):
							name = data[6:].strip()
							if name in clients:
								send("Router", sock, "A client with the name %s already exists, please choose a different name" % name)
							else:
								clients[name] = sock
								send("Router", sock, "You are now known as %s" % name)
								print("%s is now known as %s" % (sock.getpeername(), name))
						elif data.startswith("/list"):
							send("Router", sock, get_registered_clients())
						else:
							try:
								sender_name = get_name(sock)
								if len(data) < 200:
									print("(%s) %s" % (sender_name, data))
								else:
									print("(%s) %s ..." % (sender_name, data[:200]))
								msg_tuple = split_msg(data)
								send(sender_name, clients[msg_tuple[0]], msg_tuple[1])
							except NotRegisteredException as e:
								print(e)
								send("Router", sock, "Please register a name with '/name <name>'")
							except ReceiverNotGivenException as d:
								print(d[:200])
								send("Router", sock, "Please prepend a name with '<receiver name>:<message>'")
							except KeyError as k:
								print("%s is not a registered name" % k)
								send("Router", sock, "The given receiver name does not currently exist")
					else:
						# remove the socket that's broken
						if sock in sockets:
							name = get_name(sock)
							print("%s %s disconnected" % (name, sock.getpeername()))
							sockets.remove(sock)
							del clients[name]
							for c_name, c_sock in clients.items():
								# Cancel all connections with the disconnected client
								if not c_name == "Auth":
									print("Cancelling connection between %s and %s" % (c_name, name))
									send(name, c_sock, "/cancel")
								
						# at this stage, no data means probably the connection has been broken
						#broadcast(router_socket, sock, "Client (%s, %s) is offline\n" % addr) 
				except Exception as e:
					print("an error occurred: ", e)
					continue

	router_socket.close()

def get_registered_clients():
	names = "Current registered clients:"
	for name in clients.keys():
		names = "%s\n%s" % (names, name)
	return names

def get_name(sock):
	for key, val in clients.items():
		if val == sock:
			return key
	raise NotRegisteredException("Name not found for sock: %s" % sock)


def split_msg(msg):
	sep = msg.find(":")
	if sep == -1:
		raise ReceiverNotGivenException("Message does not contain a receiver name: %s" % msg)
	else:
		return (msg[:sep].strip(), msg[sep+1:].strip())


def send(sender_name, receiver_sock, msg):
	receiver_sock.send(("(%s) %s" % (sender_name, msg)).encode())


class NotRegisteredException(Exception):
	pass


class ReceiverNotGivenException(Exception):
	pass

if __name__ == "__main__":
	try:
		router()
	except KeyboardInterrupt:
		pass
