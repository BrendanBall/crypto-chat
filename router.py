import socket, select

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
		ready_to_read,ready_to_write,in_error = select.select(sockets,[],[],0)

		for sock in ready_to_read:
			if sock == router_socket: 
				new_sock, addr = router_socket.accept()
				sockets.append(new_sock)
				print("Client (%s, %s) connected" % addr)
			else:
				try:
					# get messages from the client
					data = sock.recv(4096).decode()
					if data:
						# there is something in the socket
						if data[:5] == "/name":
							name = data[6:].strip()
							clients[name] = sock
							send("Router", sock, "You are now known as %s" % name)
							print("%s is now known as %s" % (sock.getpeername(), name))
						else:
							try:
								sender_name = get_name(sock)
								print("(%s) %s" % (sender_name, data))
								sep = data.find(":")
								send(sender_name, clients[data[:sep]], data[sep+1:].strip())
							except Exception:
								send("Router", sock, "Please register a name with '/name <name>'")
					else:
						# remove the socket that's broken
						if sock in sockets:
							sockets.remove(sock)

						# at this stage, no data means probably the connection has been broken
						#broadcast(router_socket, sock, "Client (%s, %s) is offline\n" % addr) 
				except Exception as e:
					print("an error occurred",e)
					continue

	router_socket.close()

def get_name(sock):
	for key, val in clients.items():
		if val == sock:
			return key
	raise Exception("Name not found for sock: %s" % sock)

def send(sender_name, receiver_sock, msg):
	receiver_sock.send(("(%s) %s" % (sender_name, msg)).encode())
	
if __name__ == "__main__":
	router()
