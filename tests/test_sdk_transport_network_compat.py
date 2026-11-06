""""Network-boundary tests for the isolated OpenAI SDK 3.46.0 transport stack.

All servers bind to loopback. No public network, provider credential, or billable
OpenAI request is used. The candidate CI job installs HTTPX2 and cryptography.
"""
from __future__ import annotations

import ipaddress
import json
import select
import socket
import socketserver
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

httpx2 = pytest.importorskip(
    "httpx2",
    reason="candidate HTTPX2 stack is installed in its dedicated CI job",
)
cryptography = pytest.importorskip(
    "cryptography",
    reason="candidate transport job installs the project's cryptography dependency",
)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from openai import APIConnectionError, DefaultHttpx2Client, OpenAI  # noqa: E402

API_KEY = "sk-transport-network-test"
MODEL_LIST = {
    "object": "list",
    "data": [],
    "has_more": False,
    "first_id": None,
    "last_id": None,
}


def _write_loopback_certificate(tmp_path) -> tuple[str, str]:
    """Create a short-lived self-signed CA/server cert for 127.0.0.1."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "transport-test-cert.pem"
    key_path = tmp_path / "transport-test-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


def _handler_for(seen: list[str], *, delay: float = 0.0, marker: str = "target"):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen.append(self.path)
            if delay:
                time.sleep(delay)
            body = json.dumps(
                {
                    **MODEL_LIST,
                    "transport_marker": marker,
                    "request_target": self.path,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # Expected when the client correctly times out before the reply.
                pass

        def log_message(self, format: str, *args: Any) -> None:
            return

    return Handler


def _start_server(handler, *, tls_context: ssl.SSLContext | None = None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    scheme = "https" if tls_context is not None else "http"
    url = f"{scheme}://127.0.0.1:{server.server_port}/v1"
    return server, thread, url


def _stop_server(server, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def _start_connect_proxy():
    """Start a loopback-only HTTP CONNECT proxy with a bidirectional tunnel."""
    seen: list[str] = []

    class ConnectHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(3)
            reader = self.request.makefile("rb")
            request_line = reader.readline().decode("ascii", errors="replace").strip()
            parts = request_line.split()
            if len(parts) != 3 or parts[0] != "CONNECT":
                self.request.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return

            authority = parts[1]
            seen.append(authority)
            while reader.readline() not in (b"\r\n", b"\n", b""):
                pass
            host, separator, port_text = authority.rpartition(":")
            if not separator or host != "127.0.0.1":
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                return

            try:
                upstream = socket.create_connection((host, int(port_text)), timeout=3)
            except (OSError, ValueError):
                self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return

            with upstream:
                self.request.sendall(
                    b"HTTP/1.1 200 Connection Established\r\n\r\n"
                )
                self.request.setblocking(False)
                upstream.setblocking(False)
                sockets = (self.request, upstream)
                while True:
                    readable, _, exceptional = select.select(sockets, (), sockets, 3)
                    if exceptional or not readable:
                        return
                    for source in readable:
                        destination = upstream if source is self.request else self.request
                        try:
                            data = source.recv(65536)
                        except OSError:
                            return
                        if not data:
                            return
                        try:
                            destination.sendall(data)
                        except OSError:
                            return

    class ConnectServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = ConnectServer(("127.0.0.1", 0), ConnectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    proxy_url = f"http://127.0.0.1:{server.server_address[1]}"
    return server, thread, proxy_url, seen


def _exception_chain(error: BaseException):
    """Yield wrapped causes and contexts without looping on repeated exceptions."""
    pending = [error]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        yield current
        for nested in (current.__cause__, current.__context__):
            if nested is not None:
                pending.append(nested)


def test_sdk_accepts_explicit_custom_ca_context_for_https(tmp_path) -> None:
    cert_path, key_path = _write_loopback_certificate(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    seen: list[str] = []
    server, thread, base_url = _start_server(
        _handler_for(seen), tls_context=server_context
    )
    client_context = ssl.create_default_context(cafile=cert_path)
    try:
        with OpenAI(
            api_key=API_KEY,
            base_url=base_url,
            max_retries=0,
            http_client=DefaultHttpx2Client(
                verify=client_context,
                trust_env=False,
                timeout=3.0,
            ),
        ) as client:
            page = client.models.list()
            assert page.data == []
        assert seen == ["/v1/models"]
    finally:
        _stop_server(server, thread)


def test_sdk_honors_ssl_cert_file_and_trust_env_false_disables_it(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert_path, key_path = _write_loopback_certificate(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    seen: list[str] = []
    server, thread, base_url = _start_server(
        _handler_for(seen), tls_context=server_context
    )
    monkeypatch.setenv("SSL_CERT_FILE", cert_path)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    try:
        with OpenAI(
            api_key=API_KEY, base_url=base_url, max_retries=0, timeout=3.0
        ) as client:
            assert client.models.list().data == []
        assert seen == ["/v1/models"]

        # Explicitly opting out of environment trust must not inherit SSL_CERT_FILE.
        with OpenAI(
            api_key=API_KEY,
            base_url=base_url,
            max_retries=0,
            http_client=DefaultHttpx2Client(trust_env=False, timeout=3.0),
        ) as client:
            with pytest.raises(APIConnectionError) as exc_info:
                client.models.list()

        chain = tuple(_exception_chain(exc_info.value))
        assert any(
            isinstance(error, ssl.SSLCertVerificationError) for error in chain
        ) or any("CERTIFICATE_VERIFY_FAILED" in str(error) for error in chain)
        assert seen == ["/v1/models"]
    finally:
        _stop_server(server, thread)


def test_sdk_respects_environment_proxy_and_trust_env_false_bypasses_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy_seen: list[str] = []
    target_seen: list[str] = []
    proxy, proxy_thread, proxy_url = _start_server(
        _handler_for(proxy_seen, marker="proxy")
    )
    target, target_thread, target_url = _start_server(
        _handler_for(target_seen, marker="direct")
    )
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, proxy_url)
    for name in ("HTTPS_PROXY", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "")
    try:
        with OpenAI(
            api_key=API_KEY, base_url=target_url, max_retries=0, timeout=3.0
        ) as client:
            assert client.models.list().data == []
        assert len(proxy_seen) == 1
        assert proxy_seen[0].startswith(target_url)

        with OpenAI(
            api_key=API_KEY,
            base_url=target_url,
            max_retries=0,
            http_client=DefaultHttpx2Client(trust_env=False, timeout=3.0),
        ) as client:
            assert client.models.list().data == []
        assert target_seen == ["/v1/models"]
    finally:
        _stop_server(proxy, proxy_thread)
        _stop_server(target, target_thread)


def test_sdk_uses_https_connect_proxy_and_validates_target_certificate(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert_path, key_path = _write_loopback_certificate(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    target_seen: list[str] = []
    target, target_thread, target_url = _start_server(
        _handler_for(target_seen), tls_context=server_context
    )
    proxy, proxy_thread, proxy_url, proxy_seen = _start_connect_proxy()

    monkeypatch.setenv("SSL_CERT_FILE", cert_path)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    monkeypatch.setenv("HTTPS_PROXY", proxy_url)
    monkeypatch.setenv("https_proxy", proxy_url)
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "")

    try:
        with OpenAI(
            api_key=API_KEY, base_url=target_url, max_retries=0, timeout=3.0
        ) as client:
            assert client.models.list().data == []

        expected_authority = f"127.0.0.1:{target.server_port}"
        assert proxy_seen == [expected_authority]
        assert target_seen == ["/v1/models"]
    finally:
        _stop_server(proxy, proxy_thread)
        _stop_server(target, target_thread)


def test_sdk_maps_read_timeout_to_api_connection_error() -> None:
    seen: list[str] = []
    server, thread, base_url = _start_server(
        _handler_for(seen, delay=0.3)
    )
    try:
        with OpenAI(
            api_key=API_KEY,
            base_url=base_url,
            max_retries=0,
            timeout=0.05,
            http_client=DefaultHttpx2Client(trust_env=False, timeout=0.05),
        ) as client:
            with pytest.raises(APIConnectionError) as exc_info:
                client.models.list()

        chain = tuple(_exception_chain(exc_info.value))
        assert any(isinstance(error, httpx2.ReadTimeout) for error in chain)
        assert seen == ["/v1/models"]
    finally:
        _stop_server(server, thread)


def test_sdk_maps_transport_connection_failure_to_api_connection_error() -> None:
    def fail_connection(request: httpx2.Request):
        raise httpx2.ConnectError("simulated connection refusal", request=request)

    transport = httpx2.MockTransport(fail_connection)
    with OpenAI(
        api_key=API_KEY,
        base_url="https://api.openai-transport.test/v1",
        max_retries=0,
        http_client=httpx2.Client(transport=transport),
    ) as client:
        with pytest.raises(APIConnectionError):
            client.models.list()
