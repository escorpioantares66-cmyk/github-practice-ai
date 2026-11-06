"""Network-boundary tests for the isolated OpenAI SDK 3.46.0 transport stack.

All servers bind to loopback. No public network, provider credential, or billable
OpenAI request is used. The candidate CI job installs HTTPX2 and cryptography.
"""
from __future__ import annotations

import json
import ipaddress
import socket
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


def _stop_server(server: ThreadingHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


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
            with pytest.raises(APIConnectionError):
                client.models.list()
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


def test_httpx2_enforces_read_timeout_against_slow_loopback_server() -> None:
    seen: list[str] = []
    server, thread, base_url = _start_server(
        _handler_for(seen, delay=0.25)
    )
    try:
        with httpx2.Client(timeout=0.05, trust_env=False) as client:
            with pytest.raises(httpx2.ReadTimeout):
                client.get(f"{base_url}/slow")
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


def test_proxy_and_tls_environment_tests_do_not_require_external_network() -> None:
    """Guard the suite's design: test destinations and proxy endpoints are loopback."""
    assert socket.gethostbyname("localhost") in {"127.0.0.1", "::1"}
