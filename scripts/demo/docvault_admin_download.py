import getpass
import hashlib
from pathlib import Path

import requests

BASE_URL = "http://127.0.0.1:8000"
DOCUMENT_ID = "b2b4c080-f986-42b8-bcc5-6a85b1fa70e6"

FIXTURE = Path.home() / "DocVault/backend/tests/fixtures/minimal_valid.pdf"
OUTPUT = Path("/tmp/docvault_downloaded.pdf")


def main():
    session = requests.Session()

    password = getpass.getpass("Administrator password: ")

    login = session.post(
        f"{BASE_URL}/api/v1/auth/login",
        json={"username": "admin", "password": password},
        timeout=15,
    )

    print("Login HTTP status:", login.status_code)
    login.raise_for_status()

    response = session.get(
        f"{BASE_URL}/api/v1/documents/{DOCUMENT_ID}/download",
        timeout=60,
    )

    print("Download HTTP status:", response.status_code)
    response.raise_for_status()

    OUTPUT.write_bytes(response.content)

    downloaded_hash = hashlib.sha256(response.content).hexdigest()
    print("Downloaded file:", OUTPUT)
    print("Downloaded size:", len(response.content), "bytes")
    print("Downloaded SHA-256:", downloaded_hash)

    if not FIXTURE.exists():
        raise SystemExit(f"Original PDF fixture not found: {FIXTURE}")

    original_hash = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    print("Original SHA-256:  ", original_hash)

    if downloaded_hash == original_hash:
        print("\nPASS: File integrity verified. Hashes match.")
    else:
        raise SystemExit("\nFAIL: Downloaded file differs from original.")


if __name__ == "__main__":
    main()
