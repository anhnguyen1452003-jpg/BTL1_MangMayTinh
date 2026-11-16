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
daemon.httpadapter
~~~~~~~~~~~~~~~~~

This module provides a http adapter object to manage and persist 
http settings (headers, bodies). The adapter supports both
raw URL paths and RESTful route definitions, and integrates with
Request and Response objects to handle client-server communication.
"""

from .request import Request
from .response import Response
from .dictionary import CaseInsensitiveDict

import asyncio
import base64
import datetime
import http
import inspect
import json
import time

# Import streaprous raw connection functions
from streaprous_socket.streaprous_raw_connection import (
    run_conn_recv,
    run_conn_send,
    close_connection
)

class HttpAdapter:
    """
    A mutable :class:`HTTP adapter <HTTP adapter>` for managing client connections
    and routing requests.

    The `HttpAdapter` class encapsulates the logic for receiving HTTP requests,
    dispatching them to appropriate route handlers, and constructing responses.
    It supports RESTful routing via hooks and integrates with :class:`Request <Request>` 
    and :class:`Response <Response>` objects for full request lifecycle management.

    Attributes:
        ip (str): IP address of the client.
        port (int): Port number of the client.
        conn (socket): Active socket connection.
        connaddr (tuple): Address of the connected client.
        routes (dict): Mapping of route paths to handler functions.
        request (Request): Request object for parsing incoming data.
        response (Response): Response object for building and sending replies.
        conn_info (conn_struct): streaprous connection info for raw socket.
        raw_socket (socket): Raw socket for streaprous communication.
    """

    __attrs__ = [
        "ip",
        "port",
        "conn",
        "connaddr",
        "routes",
        "request",
        "response",
        "conn_info",
        "raw_socket",
    ]

    def __init__(self, ip, port, conn, connaddr, routes):
        """
        Initialize a new HttpAdapter instance.

        :param ip (str): IP address of the client.
        :param port (int): Port number of the client.
        :param conn (socket): Active socket connection.
        :param connaddr (tuple): Address of the connected client.
        :param routes (dict): Mapping of route paths to handler functions.
        """

        #: IP address.
        self.ip = ip
        #: Port.
        self.port = port
        #: Connection
        self.conn = conn
        #: Conndection address
        self.connaddr = connaddr
        #: Routes
        self.routes = routes
        #: Request
        self.request = Request()
        #: Response
        self.response = Response()
        #: streaprous connection info
        self.conn_info = None
        #: raw socket for streaprous communication
        self.raw_socket = None
        #: optional set/tuple of paths requiring authentication
        self.protected_paths = set()
        #: optional mapping {username: password} for Basic Auth validation
        self.auth_users = None

    def _detect_content_type(self, path, content):
        """Infer an appropriate Content-Type header from the request path or body."""
        clean_path = (path or "").split("?", 1)[0].lower()
        if clean_path == "/" or clean_path.endswith((".html", ".htm")):
            return "text/html; charset=utf-8"
        if clean_path.endswith(".css"):
            return "text/css"
        if clean_path.endswith(".js"):
            return "application/javascript"
        if clean_path.endswith(".json"):
            return "application/json"
        if clean_path.endswith(".png"):
            return "image/png"
        if clean_path.endswith((".jpg", ".jpeg")):
            return "image/jpeg"
        if clean_path.endswith(".ico"):
            return "image/x-icon"

        stripped = content.lstrip() if isinstance(content, bytes) else b""
        if stripped.startswith((b"{", b"[")):
            return "application/json"
        return "text/plain; charset=utf-8"

    def _build_hook_response(self, req, resp, result):
        """Serialize a route handler's return value into raw HTTP response bytes."""
        status_code = 200
        custom_headers = {}
        body = result

        if isinstance(result, tuple) and len(result) == 3:
            raw_status, raw_headers, body = result
            status_code = int(raw_status)
            if raw_headers:
                custom_headers = dict(raw_headers)

        if isinstance(body, (dict, list)):
            content = json.dumps(body).encode("utf-8")
            default_ct = "application/json"
        elif isinstance(body, bytes):
            content = body
            default_ct = self._detect_content_type(req.path, content)
        elif body is None:
            content = b""
            default_ct = "text/plain; charset=utf-8"
        elif isinstance(body, str):
            content = body.encode("utf-8")
            default_ct = self._detect_content_type(req.path, content)
        else:
            content = str(body).encode("utf-8")
            default_ct = self._detect_content_type(req.path, content)

        resp.status_code = status_code
        resp.reason = None
        resp._content = content

        has_ct = any(str(k).lower() == "content-type" for k in custom_headers)
        if not has_ct:
            resp.headers["Content-Type"] = default_ct
        for key, value in custom_headers.items():
            resp.headers[key] = value

        return resp.build_response_header(req) + content

    def parse_basic_auth(self, req):
        """Decode HTTP Basic Authorization header into (username, password) or None."""
        headers = getattr(req, "headers", None) or {}
        auth_header = ""
        for k, v in headers.items():
            if str(k).lower() == "authorization":
                auth_header = v
                break
        if not auth_header or not auth_header.lower().startswith("basic "):
            return None

        encoded = auth_header.split(" ", 1)[1].strip()
        try:
            decoded = base64.b64decode(encoded).decode("utf-8")
        except Exception:
            return None

        if ":" not in decoded:
            return None
        username, password = decoded.split(":", 1)
        return username, password

    def is_authenticated(self, req, valid_users=None):
        """Check whether request carries a valid session cookie or Basic Auth header."""
        cookies = self.extract_cookies(req)
        if cookies.get("auth") == "true" or bool(cookies.get("session_id")):
            return True

        creds = self.parse_basic_auth(req)
        if creds is None:
            return False

        username, password = creds
        if valid_users is not None:
            return bool(username) and valid_users.get(username) == password
        return bool(username and password)

    def _requires_auth(self, req):
        """Determine whether the matched route or request path requires authentication."""
        if req.hook and getattr(req.hook, "_require_auth", False):
            return True
        clean_path = (getattr(req, "path", "") or "").split("?", 1)[0]
        return clean_path in getattr(self, "protected_paths", ())

    def build_unauthorized_response(self, req=None, realm="CO3094 StreapRous", message="Unauthorized"):
        """Build an HTTP 401 Unauthorized response with WWW-Authenticate Basic header."""
        resp = Response()
        resp.status_code = 401
        resp.reason = "Unauthorized"
        resp.headers["WWW-Authenticate"] = f'Basic realm="{realm}"'
        resp.headers["Content-Type"] = "text/plain; charset=utf-8"
        resp._content = message.encode("utf-8") if isinstance(message, str) else message
        return resp.build_response_header(req) + resp._content

    def _recv_http_request(self, conn):
        """Read a full HTTP/1.1 request including its Content-Length body."""
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            chunk = conn.recv(65535)
            if not chunk:
                return buffer
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

        return header_part + b"\r\n\r\n" + body_part

    def handle_client(self, conn, addr, routes):
        """
        Handle an incoming client connection.

        This method reads the request from the socket, prepares the request object,
        invokes the appropriate route handler if available, builds the response,
        and sends it back to the client.

        :param conn (socket): The client socket connection.
        :param addr (tuple): The client's address.
        :param routes (dict): The route mapping for dispatching requests.
        """

        # Connection handler.
        self.conn = conn
        # Connection address.
        self.connaddr = addr
        # Request handler
        req = self.request
        # Response handler
        resp = self.response

        # Handle the request
        raw_msg = self._recv_http_request(conn)
        if not raw_msg:
            conn.close()
            return
        msg = raw_msg.decode("utf-8", errors="replace")
        req.prepare(msg, routes)
        print("[HttpAdapter] Invoke handle_client connection {}".format(addr))

        # Handle request hook and authentication
        response = b""
        try:
            if self._requires_auth(req) and not self.is_authenticated(req, self.auth_users):
                response = self.build_unauthorized_response(req)
            elif req.hook:
                result = req.hook(headers=req.headers, body=req.body)
                response = self._build_hook_response(req, resp, result)
            else:
                # Build response
                response = resp.build_response(req)
        except Exception as e:
            print("[HttpAdapter] Error building response: {}".format(e))
            response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"

        #print("[HttpAdapter] Response content {}".format(response))
        conn.sendall(response)
        conn.close()

    def handle_client_raw(self, raw_socket, conn_info, routes):
        """
        Handle an incoming client connection using streaprous raw connection.

        This method reads the request from the raw socket, prepares the request object,
        invokes the appropriate route handler if available, builds the response,
        and sends it back to the client using raw sockets.

        :param raw_socket (socket): The raw socket for communication.
        :param conn_info (conn_struct): The connection info for the client.
        :param routes (dict): The route mapping for dispatching requests.
        """
        # Request handler
        req = self.request
        # Response handler
        resp = self.response

        print("[HttpAdapter] Invoke handle_client_raw for {}:{}".format(conn_info.client_ip, conn_info.client_port))

        # Receive data using streaprous raw connection
        data = run_conn_recv(raw_socket, conn_info)
        
        if not data:
            print("[HttpAdapter] No data received or connection closed")
            return

        # Prepare request
        msg = data.decode("utf-8")
        req.prepare(msg, routes)
        
        # Handle request hook and authentication
        if self._requires_auth(req) and not self.is_authenticated(req, self.auth_users):
            response = self.build_unauthorized_response(req)
        elif req.hook:
            result = req.hook(headers=req.headers, body=req.body)
            response = self._build_hook_response(req, resp, result)
        else:
            # Build response - returns bytes
            response = resp.build_response(req)
        
        # Send response using streaprous raw connection
        response = response if isinstance(response, bytes) else response.encode("utf-8")
        print(f"[HttpAdapter] HTTP Response ({len(response)} bytes): {response[:200]}")
        #
        # TODO run_conn_send packet
        # run_conn_send(..)
        run_conn_send(raw_socket, conn_info, response)
        
        # Wait longer to ensure response is transmitted, client processes it, and sends ACK
        import time
        time.sleep(5.0)
        
        # Close connection with FIN packet
        #
        # TODO run_conn_send packet
        # close_connection(...)
        close_connection(raw_socket, conn_info)

    async def handle_client_coroutine(self, reader, writer):
        """
        Handle an incoming client connection using stream reader writer asynchronously.

        This method reads the request from the socket, prepares the request object,
        invokes the appropriate route handler if available, builds the response,
        and sends it back to the client.

        :param conn (socket): The client socket connection.
        :param addr (tuple): The client's address.
        :param routes (dict): The route mapping for dispatching requests.
        """
        # Request handler
        req = self.request
        # Response handler
        resp = self.response

        addr = writer.get_extra_info("peername")
        print("[HttpAdapter] Invoke handle_client_coroutine connection {})".format(addr))

        # TODO Handle the request asynchronously
        msg = await reader.read(65535)
        if not msg:
            writer.close()
            return

        req.prepare(msg.decode("utf-8", errors="replace"), routes=self.routes or {})

        # Handle request hook and authentication
        if self._requires_auth(req) and not self.is_authenticated(req, self.auth_users):
            response = self.build_unauthorized_response(req)
        elif req.hook:
            if inspect.iscoroutinefunction(req.hook):
                result = await req.hook(headers=req.headers, body=req.body)
            else:
                result = req.hook(headers=req.headers, body=req.body)
            response = self._build_hook_response(req, resp, result)
        else:
            # Build response
            #print("[HttpAdapter] Start **ASYNC** build_response with type {}".format(type(req)))
            response = resp.build_response(req)
            
        # Send all the response asynchronously
        writer.write(response)
        await writer.drain()

    def extract_cookies(self, req):
        """
        Build cookies from the :class:`Request <Request>` headers or parsed cookies.

        :param req: (Request) The :class:`Request <Request>` object.
        :rtype: dict - A dictionary of cookie key-value pairs.
        """
        if getattr(req, "cookies", None):
            return dict(req.cookies)

        cookies = {}
        headers = getattr(req, "headers", None) or {}
        cookie_str = ""
        for k, v in headers.items():
            if str(k).lower() == "cookie":
                cookie_str = v
                break
        if cookie_str:
            for pair in cookie_str.split(";"):
                if "=" in pair:
                    key, value = pair.strip().split("=", 1)
                    cookies[key.strip()] = value.strip()
        return cookies

    def build_response(self, req, resp):
        """Builds a :class:`Response <Response>` object 

        :param req: The :class:`Request <Request>` used to generate the response.
        :param resp: The  response object.
        :rtype: Response
        """
        response = Response()

        # Set encoding.
        response.encoding = get_encoding_from_headers(response.headers)
        response.raw = resp
        response.reason = response.raw.reason

        if isinstance(req.url, bytes):
            response.url = req.url.decode("utf-8")
        else:
            response.url = req.url

        # Add new cookies from the server.
        response.cookies = self.extract_cookies(req)

        # Give the Response some context.
        response.request = req
        response.connection = self

        return response

    def build_json_response(self, req, resp):
        """Builds a :class:`Response <Response>` object from JSON data

        :param req: The :class:`Request <Request>` used to generate the response.
        :param resp: The  response object.
        :rtype: Response
        """
        response = Response(req)

        # Set encoding.
        response.raw = resp

        if isinstance(req.url, bytes):
            response.url = req.url.decode("utf-8")
        else:
            response.url = req.url

        # Give the Response some context.
        response.request = req
        response.connection = self

        return response


    # def get_connection(self, url, proxies=None):
        # """Returns a url connection for the given URL. 

        # :param url: The URL to connect to.
        # :param proxies: (optional) A Requests-style dictionary of proxies used on this request.
        # :rtype: int
        # """

        # proxy = select_proxy(url, proxies)

        # if proxy:
            # proxy = prepend_scheme_if_needed(proxy, "http")
            # proxy_url = parse_url(proxy)
            # if not proxy_url.host:
                # raise InvalidProxyURL(
                    # "Please check proxy URL. It is malformed "
                    # "and could be missing the host."
                # )
            # proxy_manager = self.proxy_manager_for(proxy)
            # conn = proxy_manager.connection_from_url(url)
        # else:
            # # Only scheme should be lower case
            # parsed = urlparse(url)
            # url = parsed.geturl()
            # conn = self.poolmanager.connection_from_url(url)

        # return conn


    def add_headers(self, request):
        """
        Add headers to the request.

        This method is intended to be overridden by subclasses to inject
        custom headers. It does nothing by default.

        
        :param request: :class:`Request <Request>` to add headers to.
        """
        pass

    def build_proxy_headers(self, proxy):
        """Returns a dictionary of the headers to add to any request sent
        through a proxy. 

        :class:`HttpAdapter <HttpAdapter>`.

        :param proxy: The url of the proxy being used for this request.
        :rtype: dict
        """
        headers = {}
        #
        # TODO: build your authentication here
        #       username, password =...
        # we provide dummy auth here
        #
        import base64
        username, password = ("user1", "password")

        if username:
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("utf-8")
            headers["Proxy-Authorization"] = f"Basic {token}"

        return headers
