import sys
import socket
import select


def client():
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
    except socket.error:
        print("Unable to connect")
        sys.exit()

    print("Connected to the router. You can start sending messages")

    while True:
        socket_list = [sys.stdin, router_socket]
        ready_to_read, ready_to_write, in_error = select.select(socket_list, [], [])
        for sock in ready_to_read:
            if sock == router_socket:
                data = sock.recv(4096).decode()
                if not data:
                    sock.close()
                    print("Server has closed the connection")
                    sys.exit()
                else:
                    print(data)
            else:
                # user entered a message
                msg = sys.stdin.readline().strip()
                router_socket.send(msg.encode())
                print("[You] %s" % msg)


if __name__ == "__main__":
    client()
