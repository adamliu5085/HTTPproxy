from socket import *

sock = socket(AF_INET, SOCK_STREAM)
sock.connect(('localhost', 2100))
sock.sendall(b'GET http://localhost:8090/ HTTP/1.0\r\nHeader: custom2\r\n\r\n')

print(sock.makefile('rb').read())