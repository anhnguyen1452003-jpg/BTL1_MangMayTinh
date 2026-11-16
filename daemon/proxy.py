#
# Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course.
#
# StreapRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#

"""
daemon.proxy
~~~~~~~~~~~~~~~~~

This module implements a simple proxy server using Python's socket and threading libraries.
It routes incoming HTTP requests to backend services based on hostname mappings and returns
the corresponding responses to clients.

Requirement:
-----------------
- socket: provides socket networking interface.
- threading: enables concurrent client handling via threads.
- response: customized :class: `Response <Response>` utilities.
- httpadapter: :class: `HttpAdapter <HttpAdapter >` adapter for HTTP request processing.
- dictionary: :class: `CaseInsensitiveDict <CaseInsensitiveDict>` for managing headers and cookies.

"""
import socket
import threading
from .response import *
from .httpadapter import HttpAdapter
from .dictionary import CaseInsensitiveDict

#: A dictionary mapping hostnames to backend IP and port tuples.
#: Used to determine routing targets for incoming requests.
PROXY_PASS = {
    "192.168.56.103:8080": ('192.168.56.103', 9000),
    "app1.local": ('192.168.56.103', 9001),
    "app2.local": ('192.168.56.103', 9002),
}

RR_INDEX = {}
RR_LOCK = threading.Lock()

def forward_request(host, port, request):
    """
    Forwards an HTTP request to a backend server and retrieves the response.

    :params host (str): IP address of the backend server.
    :params port (int): port number of the backend server.
    :params request (str): incoming HTTP request.

    :rtype bytes: Raw HTTP response from the backend server. If the connection
                  fails, returns a 404 Not Found response.
    """

    backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        backend.connect((host, port))
        backend.sendall(request.encode())
        response = b""
        while True:
            chunk = backend.recv(4096)
            if not chunk:
                break
            response += chunk
        return response
    except socket.error as e:
      print("Socket error: {}".format(e))
      return (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 13\r\n"
            "Connection: close\r\n"
            "\r\n"
            "404 Not Found"
        ).encode('utf-8')
    finally:
        backend.close()


def _apply_proxy_set_headers(request, set_headers, hostname):
    """Insert or overwrite headers specified by proxy_set_header directives."""
    if not set_headers:
        return request

    sep = "\r\n\r\n" if "\r\n\r\n" in request else ("\n\n" if "\n\n" in request else None)
    if sep is not None:
        header_part, body_part = request.split(sep, 1)
        line_sep = "\r\n" if "\r\n" in header_part else "\n"
    else:
        header_part, body_part = request, ""
        line_sep = "\r\n"

    lines = header_part.split(line_sep)
    if not lines:
        return request

    req_line = lines[0]
    header_lines = lines[1:]

    resolved = {}
    for name, value in set_headers.items():
        val = hostname if value == "$host" else value
        resolved[name] = val

    override_lower = {k.lower(): (k, v) for k, v in resolved.items()}
    seen = set()
    updated_lines = []
    for line in header_lines:
        if ":" in line:
            hdr_name = line.split(":", 1)[0].strip().lower()
            if hdr_name in override_lower:
                if hdr_name not in seen:
                    orig_name, new_val = override_lower[hdr_name]
                    updated_lines.append(f"{orig_name}: {new_val}")
                    seen.add(hdr_name)
                continue
        updated_lines.append(line)

    for hdr_lower, (orig_name, new_val) in override_lower.items():
        if hdr_lower not in seen:
            updated_lines.append(f"{orig_name}: {new_val}")

    rebuilt_headers = line_sep.join([req_line] + updated_lines)
    if sep is not None:
        return rebuilt_headers + sep + body_part
    return rebuilt_headers


def _recv_full_http_request(conn):
    """Read a complete HTTP request including any Content-Length body."""
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = conn.recv(65535)
        if not chunk:
            return buffer.decode("utf-8", errors="replace")
        buffer += chunk

    header_part, body_part = buffer.split(b"\r\n\r\n", 1)
    content_length = 0
    for line in header_part.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                content_length = max(0, int(line.split(b":", 1)[1].strip()))
            except ValueError:
                content_length = 0
            break

    while len(body_part) < content_length:
        chunk = conn.recv(min(65535, content_length - len(body_part)))
        if not chunk:
            break
        body_part += chunk

    return (header_part + b"\r\n\r\n" + body_part).decode("utf-8", errors="replace")


def resolve_routing_policy(hostname, routes):
    """
    Handles an routing policy to return the matching proxy_pass.
    It determines the target backend to forward the request to.

    :params host (str): IP address of the request target server.
    :params port (int): port number of the request target server.
    :params routes (dict): dictionary mapping hostnames and location.
    """

    print(hostname)
    entry = routes.get(hostname, ('127.0.0.1:9000', 'round-robin'))
    proxy_map, policy = entry[0], entry[1]
    print(proxy_map)
    print(policy)

    proxy_host = ''
    proxy_port = '9000'
    if isinstance(proxy_map, list):
        if len(proxy_map) == 0:
            print("[Proxy] Emtpy resolved routing of hostname {}".format(hostname))
            # TODO: implement the error handling for non mapped host
            #       the policy is design by team, but it can be 
            #       basic default host in your self-defined system
            # Use a dummy host to raise an invalid connection
            
            # Trả về None để handle_client trả về lỗi 404 Not Found cho client
            return None, None
        elif len(proxy_map) == 1:
            proxy_host, proxy_port = proxy_map[0].split(":", 2)
        elif len(proxy_map) > 1:
            # Áp dụng chính sách phân phối (round-robin)
            if policy == 'round-robin':
                with RR_LOCK:
                    idx = RR_INDEX.get(hostname, 0)
                    selected = proxy_map[idx % len(proxy_map)]
                    RR_INDEX[hostname] = (idx + 1) % len(proxy_map)
            else:
                selected = proxy_map[0]
            proxy_host, proxy_port = selected.split(":", 2)
        else:
            proxy_host = '127.0.0.1'
            proxy_port = '9000'
    else:
        print("[Proxy] resolve route of hostname {} is a singulair to".format(hostname))
        proxy_host, proxy_port = proxy_map.split(":", 2)

    return proxy_host, proxy_port

def handle_client(ip, port, conn, addr, routes):
    """
    Handles an individual client connection by parsing the request,
    determining the target backend, and forwarding the request.

    The handler extracts the Host header from the request to
    matches the hostname against known routes. In the matching
    condition,it forwards the request to the appropriate backend.

    The handler sends the backend response back to the client or
    returns 404 if the hostname is unreachable or is not recognized.

    :params ip (str): IP address of the proxy server.
    :params port (int): port number of the proxy server.
    :params conn (socket.socket): client connection socket.
    :params addr (tuple): client address (IP, port).
    :params routes (dict): dictionary mapping hostnames and location.
    """

    request = _recv_full_http_request(conn)
    if not request:
        conn.close()
        return

    # Extract hostname
    hostname = ""
    for line in request.splitlines():
        if line.lower().startswith('host:'):
            hostname = line.split(':', 1)[1].strip()
            break

    print("[Proxy] {} at Host: {}".format(addr, hostname))

    entry = routes.get(hostname)
    set_headers = entry[2] if entry and len(entry) >= 3 else {}

    # Resolve the matching destination in routes and need conver port
    # to integer value
    resolved_host, resolved_port = resolve_routing_policy(hostname, routes)
    try:
        resolved_port = int(resolved_port)
    except ValueError:
        print("Not a valid integer")

    if resolved_host:
        print("[Proxy] Host name {} is forwarded to {}:{}".format(hostname,resolved_host, resolved_port))
        forwarded_request = _apply_proxy_set_headers(request, set_headers, hostname)
        response = forward_request(resolved_host, resolved_port, forwarded_request)        
    else:
        response = (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 13\r\n"
            "Connection: close\r\n"
            "\r\n"
            "404 Not Found"
        ).encode('utf-8')
    conn.sendall(response)
    conn.close()

def run_proxy(ip, port, routes):
    """
    Starts the proxy server and listens for incoming connections. 

    The process dinds the proxy server to the specified IP and port.
    In each incomping connection, it accepts the connections and
    spawns a new thread for each client using `handle_client`.
 

    :params ip (str): IP address to bind the proxy server.
    :params port (int): port number to listen on.
    :params routes (dict): dictionary mapping hostnames and location.

    """

    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        proxy.bind((ip, port))
        proxy.listen(50)
        print("[Proxy] Listening on IP {} port {}".format(ip,port))
        while True:
            conn, addr = proxy.accept()
            #
            #  TODO: implement the step of the client incomping connection
            #        using multi-thread programming with the
            #        provided handle_client routine
            #
            client_thread = threading.Thread(
                target=handle_client,
                args=(ip, port, conn, addr, routes),
                daemon=True
            )
            client_thread.start()
    except socket.error as e:
      print("Socket error: {}".format(e))

def create_proxy(ip, port, routes):
    """
    Entry point for launching the proxy server.

    :params ip (str): IP address to bind the proxy server.
    :params port (int): port number to listen on.
    :params routes (dict): dictionary mapping hostnames and location.
    """

    run_proxy(ip, port, routes)
