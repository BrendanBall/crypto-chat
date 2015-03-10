import socket, select

sockets = [] 
port = 8001

names = {}

def router():
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	server_socket.bind(("", port))
	server_socket.listen(10)
	
	sockets.append(server_socket)
	print("Server started on port %s" % port)

	while True:
		# check if there are any changes
		ready_to_read,ready_to_write,in_error = select.select(sockets,[],[],0)

		for sock in ready_to_read:
			if sock == server_socket: 
				new_sock, addr = server_socket.accept()
				sockets.append(new_sock)
				print("Client (%s, %s) connected" % addr)
			else:
				#try:
					# get messages from the client
					data = sock.recv(4096).decode()
					if data:
						print(data)
						# there is something in the socket
						if data[:5] == "/name":
							names[data[6:].strip()] = sock
							print("%s is now online" % data[6:])
						else:
							send(sock, data)  
					else:
						# remove the socket that's broken    
						if sock in sockets:
							sockets.remove(sock)

						# at this stage, no data means probably the connection has been broken
						#broadcast(server_socket, sock, "Client (%s, %s) is offline\n" % addr) 
				#except Exception(e):
				#	print("an error occurred",e)
				#	continue

	server_socket.close()

def send(sender, data):
	# find sender name
	sender_name = "OOPS"
	for key, val in names.items():
		if val == sender:
			sender_name = key
	sep = data.find(":")
	receiver = data[:sep]
	msg = data[sep+1:].strip()
	if receiver in names:
		names[receiver].send(("%s: %s" % (sender_name, msg)).encode())
	else:
		sender.send(("Could not find user %s" % receiver).encode())
	
if __name__ == "__main__":
	router()