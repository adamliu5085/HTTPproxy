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
            request_bytes, request_port, request_host = build_response(components)
            if request_port is None or request_host is None:
                skt.send(request_bytes.encode('utf-8'))

            # Create a new socket to send the response on the specified port
            else:

                # Open a new socket, send the server the parsed request, get the response, and send to client
                with socket(AF_INET, SOCK_STREAM) as send_socket:
                    send_socket.connect((request_host, request_port))
                    send_socket.sendall(request_bytes.encode('utf-8'))
                    server_response = b""
                    while True:
                        temp_response = send_socket.recv(2048)
                        if not temp_response:
                            break
                        server_response += temp_response
                    skt.sendall(server_response)

        # Otherwise the request is bad
        else:
            bad_request = "HTTP/1.0 400 Bad Request\r\n\r\n"
            skt.send(bad_request.encode('utf-8'))

def cache_blocklist_control(control_request):

    # Get the type of the request
    control_type = control_request.group(1)
    control_action = control_request.group(2)

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
            global blocked_sites
            blocked_site = control_request.group(3)
            global blocked_sites
            blocked_sites.remove(blocked_site)
        elif control_action == "flush":
            global blocked_sites
            blocked_sites.clear()
    return "200 OK"

# Build the proxy message
# Separate the components from the regex groups
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

    # TODO: CHECK DOMAIN BLOCKED HOSTS
    host = parsed_url.hostname

    # TODO: PARSE THE PROXY CACHE CONTROL AND BLOCKLIST CONTROL
    # Get the path and ensure it is valid
    path = parsed_url.path
    if path == "":
        return "HTTP/1.0 400 Bad Request\r\n\r\n", None, None
    control_pattern = re.compile(r"^/proxy/(cache|blocklist)/(enable|disable|flush|add|remove)(?:/(.+))?$")
    control_components = control_pattern.match(path)
    if control_components:
        control_response = cache_blocklist_control(control_components)
        return control_response
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
    return response, port, host


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

# TODO: CACHE
# TODO: CACHE TIME TO LIVE
# TODO: DOMAIN BLOCKLIST

# TODO: ENSURE WHEN TO CHANGE THIS
# Set the cache to disabled initially
cache_enabled = False
proxy_cache = set()

# TODO: ENSURE WHEN TO CHANGE THIS
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
