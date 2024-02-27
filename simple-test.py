from socket import *

sock = socket(AF_INET, SOCK_STREAM)
sock.connect(('localhost', 2100))
sock.sendall(b'HTTP/1.1 200 OK\r\nDate: Tue, 02 Jan 2024 20:05:47 GMT\r\nServer: Apache/2.2.24 (FreeBSD) PHP/5.3.10 with Suhosin-Patch mod_ssl/2.2.24 OpenSSL/1.0.1h DAV/2\r\nLast-Modified: Sat, 22 Jan 2022 23:19:27 GMT\r\nETag: "206accd-c2-5d633f776fdc0"\r\nAccept-Ranges: bytes\r\nContent-Length: 194\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <title>Simple Page</title>\n</head>\n\n<body>\n<h1>Simple Page</h1>\n\n<p>\n  Hello!  This is simple HTML page.\n</p>\n</body>\n\n</html>\n')

print(sock.makefile('rb').read())