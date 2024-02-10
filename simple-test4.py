from socket import *

# Create a TCP socket
with socket(AF_INET, SOCK_STREAM) as server_socket:

    # Bind the socket to the given port
    server_address = ('localhost', 8191)
    server_socket.bind(server_address)

    # Listen for incoming connections
    server_socket.listen(1)
    print(f"Server listening on {server_address}")

    while True:
        # Accept a connection
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")

        # Receive data from the client
        data = client_socket.recv(1024)
        print(f"Received data on port {8191}: {data.decode('utf-8')}")

        # Close the connection
        client_socket.close()