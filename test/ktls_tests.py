import array
import os
import socket
import unittest
import ssl
import time

from contextlib import suppress
from io import DEFAULT_BUFFER_SIZE as BUF_SIZE
from urllib.parse import urlparse, urlunparse

TINIKTLS_FD = int(os.environ["TINIKTLS_FD"])

GET_REQUEST = """GET / HTTP/1.1
Host: www.example.com
User-Agent: curl/8.9.1
Accept: */*

"""

CERTS_PATH = os.path.join(os.path.dirname(__file__), "certs")
RSA_CERT = os.path.join(CERTS_PATH, "rsa-cert.pem")
RSA_KEY = os.path.join(CERTS_PATH, "rsa-key.pem")
EC_CERT = os.path.join(CERTS_PATH, "ec-cert.pem")
EC_KEY = os.path.join(CERTS_PATH, "ec-key.pem")
UNEXPECTED_CERT = os.path.join(CERTS_PATH, "unexpected-cert.pem")
UNEXPECTED_KEY = os.path.join(CERTS_PATH, "unexpected-key.pem")

TLS12_RSA_CIPHERS = [
	"ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-RSA-CHACHA20-POLY1305",
];

TLS12_ECDSA_CIPHERS = [
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-CHACHA20-POLY1305",
];

TLS13_CIPHERS = [ 
	"TLS_AES_128_GCM_SHA256",
	"TLS_AES_256_GCM_SHA384",
	"TLS_CHACHA20_POLY1305_SHA256",
]

class TiniKTLS:
    """TiniKTLS Client Driver"""
    def __init__(self) -> None:
        fd = int(os.environ.get("TINIKTLS_FD", "0"))
        if fd < 3:
            raise KeyError("TINIKTLS_FD env var missing - was this launched by tiniktls?")
        self._tiniktls = socket.fromfd(fd,socket.AF_UNIX, socket.SOCK_STREAM, 0)
        os.close(fd) # socked.fromfd duplicates the fd

    # @staticmethod
    # def _resolve_host(hostname: str) -> str:
    #     addrinfo = socket.getaddrinfo(
    #         "www.example.com", 443, family=socket.AF_INET, type=socket.SOCK_STREAM,
    #     )
    #     assert addrinfo, "gaierror was not raised"
    #     return addrinfo[0][4][0]

    def _sendmsg(self, msg: str) -> None:
        self._tiniktls.sendall(msg.encode("utf-8"))

    def _recvmsg(self, flags: int = 0) -> (str, socket.socket | None):
        fds = array.array("i")   # Array of ints
        msg, ancdata, flags, addr = self._tiniktls.recvmsg(1024, socket.CMSG_LEN(fds.itemsize), flags)
        if not ancdata:
            return msg, None
        assert len(ancdata) == 1
        cmsg_level, cmsg_type, cmsg_data = ancdata[0]
        assert cmsg_level == socket.SOL_SOCKET
        assert cmsg_type == socket.SCM_RIGHTS
        # Append data, ignoring any truncated integers at the end.
        fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
        sock = socket.fromfd(fds[0], socket.AF_INET, socket.SOCK_STREAM, 0)
        os.close(fds[0]) # socked.fromfd duplicates the fd
        return msg, sock

    # @staticmethod
    # def _is_valid_ip(addr: str) -> bool:
    #     with suppress(OSError):
    #         socket.inet_pton(socket.AF_INET, addr)
    #         return True
    #     with suppress(OSError):
    #         socket.inet_pton(socket.AF_INET6, addr)
    #         return True
    #     return False

    def connect(self, url: str) -> None:
        url_info = urlparse(url)
        #if not TiniKTLS._is_valid_ip(url_info.hostname):
        #    url_info.hostname = TiniKTLS._resolve_host(url_info.hostname)
        #    url = urlunparse(url_info)
        msg = f"CONNECT {url}\n"
        self._sendmsg(msg)

    def accept(self, url: str) -> None:
        self._sendmsg(f"ACCEPT {url}\n")

    def close(self, url: str) -> None:
        self._sendmsg(f"CLOSE {url}\n")

    def wait_socket(self, url: str, cmd: str | None = None) -> socket.socket:
        while True:
            line, sock = self._recvmsg(socket.MSG_PEEK)
            if not line.endswith(b'\n'):
                raise socket.error(f"invalid message received: {line}")
            words = line[:-1].split(b' ', 3)
            if len(words) < 2:
                raise socket.error(f"too short message received: {line}")
            if cmd is not None and words[1].decode("utf-8") != cmd:
                raise socket.error(f"wrong command in response: {line}")
            if words[2].decode("utf-8") != url:
                raise socket.error(f"wrong url in response: {line}")
            _ = self._recvmsg()  # consume the message
            if words[0] != b"OK":
                raise socket.error(line)
            return sock


class TestKTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tiniktls = TiniKTLS()

    # def test_tcp_connect_example_com(self):
    #     url = "tcp://www.example.com:80"
    #     self.tiniktls.connect(url)
    #     with self.tiniktls.wait_socket(url) as sock:
    #         sock.sendall(GET_REQUEST.encode("utf-8"))
    #         data = sock.recv(BUF_SIZE)
    #         print(f"HTTP response received ({len(data)} bytes)")

    # def test_tls_connect_example_com(self):
    #     url = "tls://www.example.com:443"
    #     self.tiniktls.connect(url)
    #     with self.tiniktls.wait_socket(url) as sock:
    #         sock.sendall(GET_REQUEST.encode("utf-8"))
    #         data = sock.recv(BUF_SIZE)
    #         print(f"HTTP response received ({len(data)} bytes)")

    @staticmethod
    def _test_echo(client: socket.socket, server: socket.socket) -> None:
        client.sendall(GET_REQUEST.encode("utf-8"))
        server_data = server.recv(BUF_SIZE)
        assert server_data.decode("utf-8") == GET_REQUEST
        server.sendall(server_data) # echo
        client_data = client.recv(BUF_SIZE)
        assert client_data.decode("utf-8") == GET_REQUEST

    def _test_tls_connect_then_echo(self, url: str, cert: str, key: str) -> None:
        with socket.create_server(("127.0.0.1", 10443)) as tcp_socket:
            tcp_socket.listen()
            self.tiniktls.connect(url)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            with context.wrap_socket(tcp_socket, server_side=True) as tls_socket:
                with tls_socket.accept()[0] as server:
                    with self.tiniktls.wait_socket(url) as client:
                        TestKTLS._test_echo(client, server)

    def _test_tls_accept_then_echo(self, query: str, cert: str):
        url = f"tls://127.0.0.1:10443?{query}"
        self.tiniktls.accept(url)
        try:
            with TestKTLS._create_connection("127.0.0.1", 10443, 1) as tcp_sock:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_verify_locations(cert)            
                with context.wrap_socket(tcp_sock, server_hostname="127.0.0.1") as client:
                    with self.tiniktls.wait_socket(url) as server:
                        TestKTLS._test_echo(client, server)
        finally:
            self.tiniktls.close(url)
            self.tiniktls.wait_socket(url)


    def _test_tls_echo(self, query: str) -> None:
        url = f"tls://127.0.0.1:10443?{query}"
        self.tiniktls.accept(url)
        try:
            self.tiniktls.connect(url)
            with self.tiniktls.wait_socket(url) as server:
                with self.tiniktls.wait_socket(url) as client:
                    TestKTLS._test_echo(client, server)
        finally:
            self.tiniktls.close(url)
            self.tiniktls.wait_socket(url)

    @staticmethod
    def _create_connection(addr: str, port: int, timeout: int) -> socket.socket:
        #time.sleep(1)
        deadline = time.time() + timeout
        last_error = None
        while time.time() < deadline:
            try:
                return socket.create_connection((addr, port))
            except socket.error as err:
                last_error = err
        raise TimeoutError from last_error

    def test_tcp_connect_ipaddr(self):
        url = "tcp://127.0.0.1:10080"
        with socket.create_server(("localhost", 10080)) as tcp_socket:
            tcp_socket.listen()
            self.tiniktls.connect(url)
            with tcp_socket.accept()[0] as server:
                with self.tiniktls.wait_socket(url) as client:
                    TestKTLS._test_echo(client, server)

    def test_tcp_connect_hostname(self):
        url = "tcp://localhost:10080"
        with socket.create_server(("localhost", 10080)) as tcp_socket:
            tcp_socket.listen()
            self.tiniktls.connect(url)
            with tcp_socket.accept()[0] as server:
                with self.tiniktls.wait_socket(url) as client:
                    TestKTLS._test_echo(client, server)

    def test_tcp_connect_error(self):
        url = "tcp://127.0.0.1:10081"
        self.tiniktls.connect(url)
        with self.assertRaises(socket.error) as context:
            self.tiniktls.wait_socket(url)

    def test_tls_connect(self):
        url = "tls://localhost:10443"
        self._test_tls_connect_then_echo(url, RSA_CERT, RSA_KEY)

    def test_tls_connect_tls12(self):
        url = "tls://localhost:10443/?tls=1.2"
        self._test_tls_connect_then_echo(url, RSA_CERT, RSA_KEY)

    def test_tls_connect_tls13(self):
        url = "tls://localhost:10443/?tls=1.3"
        self._test_tls_connect_then_echo(url, RSA_CERT, RSA_KEY)

    # def test_tls_connect_tls12_bad_cipher(self):
    #     # server key is RSA
    #     url = "tls://127.0.0.1:10443/?tls=1.2&ciphers=ECDHE-ECDSA-AES128-GCM-SHA256"
    #     with self.assertRaises(ssl.SSLError):
    #         self._test_tls_connect_then_echo(url, RSA_CERT, RSA_KEY)

    # def test_tls_connect_tls12_bad_cipher(self):
    #     # server key is RSA so ECDSA only is expected to fail
    #     url = "tls://127.0.0.1:10443/?tls=1.2&ciphers=ECDHE-ECDSA-AES128-GCM-SHA256"
    #     with self.assertRaises(ssl.SSLError):
    #         self._test_tls_connect_then_echo(url, RSA_CERT, RSA_KEY)

    # def test_tls_connect_self_signed(self):
        # url = "tls://127.0.0.1:10443"
        # try:
        #     self._test_tls_connect_then_echo(url, RSA_CERT, RSA_KEY)
        #     self.fail("expecting ssl.SSLError")
        # except ssl.SSLError:
        #     pass

    def test_tls_connect_no_verify(self):
        url = "tls://localhost:10443?verify=0"
        self._test_tls_connect_then_echo(url, UNEXPECTED_CERT, UNEXPECTED_KEY)

    def test_tcp_accept(self):
        url = "tcp://127.0.0.1:10080"
        self.tiniktls.accept(url)
        try:
            with TestKTLS._create_connection("127.0.0.1", 10080, 1) as client:
                with self.tiniktls.wait_socket(url) as server:
                    TestKTLS._test_echo(client, server)
        finally:
            self.tiniktls.close(url)
            self.tiniktls.wait_socket(url)

    def test_tcp_accept_backlog(self):
        url = "tcp://127.0.0.1:10080?backlog=3"
        self.tiniktls.accept(url)
        try:
            with TestKTLS._create_connection("127.0.0.1", 10080, 1) as client:
                with self.tiniktls.wait_socket(url) as server:
                    TestKTLS._test_echo(client, server)
        finally:
            self.tiniktls.close(url)
            self.tiniktls.wait_socket(url)

    def test_tls_accept(self):
        query = f"cert={RSA_CERT}&key={RSA_KEY}"
        self._test_tls_accept_then_echo(query, RSA_CERT)

    def test_tls_accept_tls12(self):
        query = f"cert={RSA_CERT}&key={RSA_KEY}&tls=1.2"
        self._test_tls_accept_then_echo(query, RSA_CERT)

    def test_tls_accept_tls13(self):
        query = f"cert={RSA_CERT}&key={RSA_KEY}&tls=1.3"
        self._test_tls_accept_then_echo(query, RSA_CERT)

    def test_tls12_ciphers(self):
        for cipher in TLS12_RSA_CIPHERS:
            query = f"cert={RSA_CERT}&key={RSA_KEY}&tls=1.2&ciphers={cipher}"
            self._test_tls_echo(query)
        for cipher in TLS12_ECDSA_CIPHERS:
            query = f"cert={EC_CERT}&key={EC_KEY}&tls=1.2&ciphers={cipher}"
            self._test_tls_echo(query)

    def test_tls13_ciphers(self):
        for cipher in TLS13_CIPHERS:
            query = f"cert={RSA_CERT}&key={RSA_KEY}&tls=1.3&ciphers={cipher}"
            self._test_tls_echo(query)
        for cipher in TLS13_CIPHERS:
            query = f"cert={EC_CERT}&key={EC_KEY}&tls=1.3&ciphers={cipher}"
            self._test_tls_echo(query)

if __name__ == '__main__':
    unittest.main(warnings='ignore')  # the ResourceWarning is wrong