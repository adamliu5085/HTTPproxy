"""
File Name: HTTPproxy.py
Author: ADAM LIU
Date: February 2024

Description: This HTTP/1.0 proxy will accept and send client request through TCP under the following procedures.
    Multithreaded: This proxy will multithread and parallelize the requests sent and received with a TCO connection.
    Cache: This proxy caches all server responses when enabled.
    Domain Blocking: This proxy will block specific hosts and associated ports if enabled.
"""
import signal
from optparse import OptionParser
import sys
from socket import *
import re
from urllib.parse import urlparse
import threading
from datetime import datetime


def ctrl_c_pressed(signal, frame):
    """
    Signal handler for pressing ctrl-c
    param signal: Keyboard Signal
    param frame: Frame
    """
    sys.exit(0)


def cache(cache_hostname, cache_path, cache_port, server_skt, og_request):
    """
    This function will check the proxys cache and either return the
    version it holds or acquires a new one from the origin server.

    param cache_hostname: The hostname of the request.
    param cache_path: The path for the host.
    param cache_port: The port specified with the request.
    param server_skt: The origin servers socket.
    param og_request: The regular parsed request in the case of no conditional get.

    return: The origin servers response of a cached version of the clients request.
    """
    global lock
    global proxy_cache

    # The proxy checks if Obj is in the proxy’s cache and assigns it.
    cache_identity = cache_hostname + str(cache_port) + cache_path
    with lock:
        exists_in_cache = proxy_cache.__contains__(cache_identity)
    if exists_in_cache:
        with lock:
            obj = proxy_cache.get(cache_identity)

        # Find the last modified time and append it to the request to make it conditional or fabricate one.
        last_modified_pattern = r'Last-Modified:\s*(.*)'
        last_modified = re.search(last_modified_pattern, obj)
        current_time = datetime.now()
        timestamp = current_time.strftime('%a, %d %b %Y %H:%M:%S GMT')
        if last_modified:
            timestamp = last_modified.group(1)
        conditional_get = og_request + "If-Modified-Since: " + timestamp

        # Verifies that is cached copy of Obj is up-to-date by issuing a “conditional GET” to the origin server.
        server_skt.sendall(conditional_get.encode("utf-8"))

        # The proxy receives the response from the origin server.
        conditional_response = b""
        while True:
            t = server_skt.recv(2048)
            if not t:
                break
            conditional_response += t

        # If response indicates that Obj has not been modified since it was cached, then cache is up-to-date.
        was_modified_pattern = r'304 Not Modified'
        if re.search(was_modified_pattern, conditional_response.decode("utf-8")):
            return obj.encode("utf-8")

        # Otherwise, the server’s response will contain an updated version of Obj.
        return conditional_response

    # If not, the proxy requests Obj from the origin server using a GET request.
    else:
        server_skt.sendall(og_request.encode('utf-8'))
        conditional_response = b""
        while True:
            t = server_skt.recv(2048)
            if not t:
                break
            conditional_response += t

        # Updates cache with the up-to-date version of Obj and the time at which Obj was last modified.
        success_pattern = r'200 OK'
        if re.search(success_pattern, conditional_response.decode("utf-8")):
            with lock:
                proxy_cache[cache_identity] = conditional_response.decode("utf-8")

        # The proxy responds to the client with the up-to-date version of Obj.
        return conditional_response


def cache_blocklist_control(control_request):
    """
    This function controls the cache properties and the blocklist properties.
    Allows for cache to be enabled or disabled as per clients request

    Parameters:
    - control_request: The request from the client.

    Returns:
    The status (200 OK) of the request.
    """
    global cache_enabled
    global blocklist_enabled
    global blocked_sites
    global lock

    # Get the type of the request.
    control_type = control_request.group(1)
    control_action = control_request.group(2)

    with lock:
        # Cache control.
        if control_type == "cache":
            if control_action == "enable":
                cache_enabled = True
            elif control_action == "disable":
                cache_enabled = False
            elif control_action == "flush":
                proxy_cache.clear()

        # Blocklist control.
        elif control_type == "blocklist":
            if control_action == "enable":
                blocklist_enabled = True
            elif control_action == "disable":
                blocklist_enabled = False
            elif control_action == "add":
                blocked_site = control_request.group(3)
                blocked_sites.add(blocked_site)
                print("Added: " + blocked_site)
            elif control_action == "remove":
                blocked_site = control_request.group(3)
                blocked_sites.remove(blocked_site)
            elif control_action == "flush":
                blocked_sites.clear()
    return "HTTP/1.0 200 OK\r\n\r\n"


def build_response(request_components):
    """
    This function build the request from the client into the proper form.

    Parameters:
    - request_components: The components that the request must include to the origin server.

    Returns:
    The proper formatted request to be sent to the origin server.
    """
    global lock
    global blocklist_enabled
    global blocked_sites

    # If the request is not GET, it is not implemented.
    method = request_components.group(1)
    if method != "GET":
        return "HTTP/1.0 501 Not Implemented\r\n\r\n", None, None, None

    # Check the http version.
    http_version = request_components.group(3)
    if http_version != "HTTP/1.0":
        return "HTTP/1.0 400 Bad Request\r\n\r\n", None, None, None

    # Obtain the url attributes.
    url = request_components.group(2)
    url_pattern = re.compile(r'^([a-zA-Z]+)://([^/]+)(/.*)?$')
    if not (url_pattern.match(url)):
        return "HTTP/1.0 400 Bad Request\r\n\r\n", None, None, None
    parsed_url = urlparse(url)

    # Default the port to 80 otherwise parse out the intended port.
    parsed_port = 80
    if ":" in parsed_url.netloc:
        parsed_port = int(parsed_url.netloc.split(":")[1])
    host = parsed_url.hostname

    # Check if the host and associated port is blocked.
    with lock:
        if blocklist_enabled:
            for item in blocked_sites:
                if item in host or host in item:
                    return "HTTP/1.0 403 Forbidden\r\n\r\n", None, None, None

    # Get the path and ensure it is valid.
    path = parsed_url.path
    if path == "":
        return "HTTP/1.0 400 Bad Request\r\n\r\n", None, None, None

    # Parse the control patterns to change the state.
    control_pattern = re.compile(r"^/proxy/(cache|blocklist)/(enable|disable|flush|add|remove)(?:/(.+))?$")
    control_components = control_pattern.match(path)
    if control_components:
        control_response = cache_blocklist_control(control_components)
        return control_response, None, None, None

    # Build and return the request, if there are additional headers, include them.
    if request_components.group(4):
        other_headers = request_components.group(4)
        modified_headers = re.sub(r'Connection: [a-zA-Z0-9-]+\s+', "", other_headers)
        response = method + " " + path + " " + http_version + "\r\n" + \
                   "Host: " + host + "\r\n" + \
                   "Connection: close" + "\r\n" + \
                   modified_headers + \
                   "\r\n\r\n"

    # Otherwise don't include any other headers.
    else:
        response = method + " " + path + " " + http_version + "\r\n" + \
                   "Host: " + host + "\r\n" + \
                   "Connection: close" + "\r\n\r\n"
    return response, parsed_port, host, path


def proxy(skt):
    """
    This function allows a newly accepted TCP connection to process its requests to the origin server.
    Sends the request content back to the client either from the origin server or from the proxy cache in enabled.
    Does not return the content if it is blocked, given that the blocklist has been enabled.

    Parameters:
    - skt: The new clients socket opened from TCP
    """
    global cache_enabled
    global lock

    # Begin to parse the accepted request.
    with skt as skt:

        # Parse receive request to a string.
        parsed_request = b""
        while True:
            if parsed_request.endswith(b"\r\n\r\n"):
                break
            temp = skt.recv(2048)
            parsed_request += temp

        # Read the data from the client and check for properly formatted HTTP request.
        request_pattern = re.compile(r"^([A-Z]+) ([^ ]+)\s+(HTTP/\d+\.\d+)\s+(([\w-]+: .+(?:\n[\t ]+.+)*\s+)*)$")
        components = request_pattern.match(parsed_request.decode('utf-8'))

        # Send the request to client if valid.
        if components:

            # Call the response builder function and send it.
            request_bytes, request_port, request_host, request_path = build_response(components)
            if request_port is None or request_host is None:
                skt.send(request_bytes.encode('utf-8'))

            # Open a new socket, send the server the parsed request, get the response, and send to client.
            else:
                with socket(AF_INET, SOCK_STREAM) as send_socket:
                    send_socket.connect((request_host, request_port))
                    with lock:
                        cache_status = cache_enabled

                    # If the cache is enabled, then follow cache procedures.
                    if cache_status:
                        server_response = cache(request_host, request_path, request_port, send_socket, request_bytes)
                        skt.sendall(server_response)

                    # Otherwise send and receive request as normal.
                    else:
                        send_socket.sendall(request_bytes.encode('utf-8'))
                        server_response = b""
                        while True:
                            temp_response = send_socket.recv(2048)
                            if not temp_response:
                                break
                            server_response += temp_response
                        skt.sendall(server_response)

        # Otherwise the request is bad.
        else:
            bad_request = "HTTP/1.0 400 Bad Request\r\n\r\n"
            skt.send(bad_request.encode('utf-8'))


# START OF PROGRAM EXECUTION.
# Parse out the command line server address and port number to listen to.
parser = OptionParser()
parser.add_option('-p', type='int', dest='serverPort')
parser.add_option('-a', type='string', dest='serverAddress')
(options, args) = parser.parse_args()

# Assign the port and address if specified otherwise default.
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
# This global variable toggles the cache, initially disabled.
cache_enabled = False

# This global map contains the proxy cache.
proxy_cache = {}

# This global variable is the blocklist toggle, initially disabled.
blocklist_enabled = False

# This global set contains the blocked sites.
blocked_sites = set()

# Open a socket to receive from clients.
with socket(AF_INET, SOCK_STREAM) as listen_socket:
    # Setup a socket to listen
    listen_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listen_socket.bind((address, port))

    # Accept and handle connections.
    while True:
        # Listen and accept incoming connections.
        listen_socket.listen()
        skt, addr = listen_socket.accept()

        # Handle request with a new thread.
        threading.Thread(target=proxy, args=(skt,)).start()
