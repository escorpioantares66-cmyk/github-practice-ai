"""Live, direct HTTPS trust-store check for the isolated Termux SDK candidate.

No API credentials are used. The endpoint is configurable because some networks
block public test hosts. Proxy environment variables are deliberately ignored.
"""
from __future__ import annotations

import os
import platform
import ssl
import sys
import sysconfig
from importlib.metadata import version
from pathlib import Path

import certifi
import httpx2
import openai


def main() -> None:
    system_ca = ssl.get_default_verify_paths().cafile
    certifi_ca = certifi.where()
    url = os.environ.get("TERMUX_TLS_TEST_URL", "https://example.com/")

    print("=== Termux SDK transport evidence ===")
    print(f"Python: {platform.python_version()}")
    print(f"Platform: {sys.platform} / {platform.machine()} / {sysconfig.get_platform()}")
    print(f"OpenSSL: {ssl.OPENSSL_VERSION}")
    print(f"OpenAI SDK: {openai.__version__}")
    print(f"HTTPX2: {version('httpx2')}")
    print(f"System CA bundle: {system_ca}")
    print(f"Certifi CA bundle: {certifi_ca}")
    print(f"Direct HTTPS probe URL: {url}")
    print("Proxy environment: bypassed (trust_env=False)")

    bundles = (("Termux OpenSSL", system_ca), ("Certifi", certifi_ca))
    for label, ca_path in bundles:
        if not ca_path or not Path(ca_path).is_file():
            raise SystemExit(f"{label} CA bundle is missing: {ca_path!r}")
        context = ssl.create_default_context(cafile=ca_path)
        with httpx2.Client(
            verify=context,
            trust_env=False,
            timeout=httpx2.Timeout(20.0),
            follow_redirects=True,
        ) as client:
            response = client.get(url)
        print(f"{label} CA: PASS (HTTP {response.status_code})")

    print("Both CA bundles completed direct HTTPS with certificate verification.")


if __name__ == "__main__":
    main()
