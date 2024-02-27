# ADAM LIU
# HTTP Proxy 1.0

import signal
from optparse import OptionParser
import sys
from socket import *
import re
from urllib.parse import urlparse
import threading


# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)


# TODO: Put function definitions here

def cache(cache_hostname, cache_path, cache_port, server_skt, server_connection, og_request):

    cache_identity = cache_hostname + cache_port + cache_path

    # The proxy checks if Obj is in the proxy’s cache.
    lock.acquire()
    try:
        if proxy_cache.__contains__(cache_identity):
            obj = proxy_cache.get(cache_identity)

            # Find the last modified time
            last_modified_pattern = r'If-Modified-Since:\s*(.*)'
            last_modified = re.search(last_modified_pattern, obj)
            timestamp = ""
            if last_modified:
                timestamp = last_modified.group(1)
            conditional_get = "GET " + cache_path + " HTTP/1.0" + "\r\n" + "Host: " + cache_hostname + "\r\n" + "If-Modified-Since: " + timestamp

            # If so, the proxy verifies that is cached copy of Obj is up-to-date by issuing a “conditional GET” to the origin server. The proxy receives the response from the origin server.
            server_skt.conect(server_connection)
            server_skt.sendall(conditional_get.encode("utf-8"))
            conditional_response = b""
            while True:
                t = server_skt.recv(2048)
                if not t:
                    break
                conditional_response += t

            # If the server’s response indicates that Obj has not been modified since it was cached by the proxy, then the proxy already has an up-to-date copy of Obj.
            was_modified_pattern = r'304 Not Modified'
            if re.search(was_modified_pattern, conditional_response.decode("utf-8")):
                return obj.encode("utf-8")

            # Otherwise, the server’s response will contain an updated version of Obj.
            return conditional_response

        # If not, the proxy requests Obj from the origin server using a GET request.
        else:
            server_skt.sendall(og_request)
            conditional_response = b""
            while True:
                t = server_skt.recv(2048)
                if not t:
                    break
                conditional_response += t

            # The proxy updates its cache with the up-to-date version of Obj and the time at which Obj was last modified.
            success_pattern = r'200 OK'
            if re.search(success_pattern, conditional_response.decode("utf-8")):
                proxy_cache[cache_identity] = conditional_response.decode("utf-8")

            # The proxy responds to the client with the up-to-date version of Obj.
            return conditional_response
    finally:
        lock.release()


def cache_blocklist_control(control_request):

    # Get the type of the request
    control_type = control_request.group(1)
    control_action = control_request.group(2)

    lock.acquire()
    try:
        # Cache control
        if control_type == "cache":
            if control_action == "enable":
                global cache_enabled
                cache_enabled = True
            elif control_action == "disable":
                global cache_enabled
                cache_enabled = False
            elif control_action == "flush":
                global proxy_cache
                proxy_cache.clear()

        # Blocklist control
        if control_type == "blocklist":
            if control_action == "enable":
                global blocklist_enabled
                blocklist_enabled = True
            elif control_action == "disable":
                global blocklist_enabled
                blocklist_enabled = False
            elif control_action == "add":
                blocked_site = control_request.group(3)
                global blocked_sites
                blocked_sites.add(blocked_site)
            elif control_action == "remove":
                blocked_site = control_request.group(3)
                global blocked_sites
                blocked_sites.remove(blocked_site)
            elif control_action == "flush":
                global blocked_sites
                blocked_sites.clear()
        return "HTTP/1.0 200 OK\r\n\r\n"
    finally:
        lock.release()



# Build the proxy message and separate the components
def build_response(request_components):
    # If the request is not GET, it is not implemented
    method = request_components.group(1)
    if method != "GET":
        return "HTTP/1.0 501 Not Implemented\r\n\r\n", None, None

    # Check the http version
    http_version = request_components.group(3)
    if http_version != "HTTP/1.0":
        return "HTTP/1.0 400 Bad Request\r\n\r\n", None, None

    # Obtain the url attributes
    url = request_components.group(2)
    url_pattern = re.compile(r'^([a-zA-Z]+)://([^/]+)(/.*)?$')
    if not (url_pattern.match(url)):
        return "HTTP/1.0 400 Bad Request\r\n\r\n", None, None
    parsed_url = urlparse(url)

    # Check if the host is blocked or not
    host = parsed_url.hostname
    lock.acquire()
    try:
        if blocklist_enabled:
            for item in blocked_sites:
                if item in host:
                    return "HTTP/1.0 403 Forbidden\r\n\r\n", None, None
    finally:
        lock.release()

    # Get the path and ensure it is valid
    path = parsed_url.path
    if path == "":
        return "HTTP/1.0 400 Bad Request\r\n\r\n", None, None

    # Parse the control patterns to change the state
    control_pattern = re.compile(r"^/proxy/(cache|blocklist)/(enable|disable|flush|add|remove)(?:/(.+))?$")
    control_components = control_pattern.match(path)
    if control_components:
        lock.acquire()
        try:
            control_response = cache_blocklist_control(control_components)
            return control_response, None, None
        finally:
            lock.release()

    # Default the port to 80 otherwise parse out the intended port
    port = 80
    if ":" in parsed_url.netloc:
        port = int(parsed_url.netloc.split(":")[1])

    # Build and return the request, if there are additional headers, include them
    if request_components.group(4):
        other_headers = request_components.group(4)
        modified_headers = re.sub(r'Connection: [a-zA-Z0-9-]+\s+', "", other_headers)
        response = method + " " + path + " " + http_version + "\r\n" + \
                   "Host: " + host + "\r\n" + \
                   "Connection: close" + "\r\n" + \
                   modified_headers + \
                   "\r\n\r\n"

    # Otherwise don't include any other headers
    else:
        response = method + " " + path + " " + http_version + "\r\n" + \
                   "Host: " + host + "\r\n" + \
                   "Connection: close" + "\r\n\r\n"
    return response, port, host, path


def proxy(skt):
    # Begin to parse the accepted request
    with skt as skt:

        # Parse receive request to a string
        parsed_request = b""
        while True:
            if parsed_request.endswith(b"\r\n\r\n"):
                break
            temp = skt.recv(2048)
            parsed_request += temp

        # Read the data from the client and check for properly formatted HTTP request.
        request_pattern = re.compile(r"^([A-Z]+) ([^ ]+)\s+(HTTP/\d+\.\d+)\s+(([\w-]+: .+(?:\n[\t ]+.+)*\s+)*)$")
        components = request_pattern.match(parsed_request.decode("utf-8"))

        # Send the request to client if valid
        if components:

            # Call the response builder function and send it
            request_bytes, request_port, request_host, request_path = build_response(components)
            if request_port is None or request_host is None:
                skt.send(request_bytes.encode('utf-8'))

            # Create a new socket to send the response on the specified port
            else:

                # Open a new socket, send the server the parsed request, get the response, and send to client
                with socket(AF_INET, SOCK_STREAM) as send_socket:

                    lock.acquire()
                    try:
                        # Consult cache
                        if cache_enabled:
                            server_response = cache(request_host, request_path, request_port, send_socket, (request_host, request_port), request_bytes)
                            skt.sendall(server_response)
                        else:
                            send_socket.connect((request_host, request_port))
                            send_socket.sendall(request_bytes.encode('utf-8'))
                            server_response = b""
                            while True:
                                temp_response = send_socket.recv(2048)
                                if not temp_response:
                                    break
                                server_response += temp_response
                            skt.sendall(server_response)
                    finally:
                        lock.release()
        # Otherwise the request is bad
        else:
            bad_request = "HTTP/1.0 400 Bad Request\r\n\r\n"
            skt.send(bad_request.encode('utf-8'))



# Start of program execution
# Parse out the command line server address and port number to listen to
parser = OptionParser()
parser.add_option('-p', type='int', dest='serverPort')
parser.add_option('-a', type='string', dest='serverAddress')
(options, args) = parser.parse_args()

# Assign the port and address if specified otherwise default
port = options.serverPort
address = options.serverAddress
if address is None:
    address = 'localhost'
if port is None:
    port = 2100

# Set up signal handling (ctrl-c)
signal.signal(signal.SIGINT, ctrl_c_pressed)

# Create a lock
lock = threading.Lock()

# Set the cache to disabled initially
cache_enabled = False
proxy_cache = {}

# Set the blocklist to disabled initially, and create an empty set
blocklist_enabled = False
blocked_sites = set()

# Open a socket to receive from clients
with socket(AF_INET, SOCK_STREAM) as listen_socket:

    # Setup a socket to listen
    listen_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listen_socket.bind((address, port))

    # Accept and handle connections
    while True:

        # Listen and accept incoming connections
        listen_socket.listen()
        skt, addr = listen_socket.accept()

        # Handle request with a new thread
        threading.Thread(target=proxy, args=(skt,)).start()
