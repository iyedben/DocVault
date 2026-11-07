import getpass
import hashlib
from pathlib import Path

import requests

BASE_URL = "http://127.0.0.1:8000"
FIXTURE = Path.home() / "DocVault/backend/tests/fixtures/minimal_valid.pdf"


def main():
    if not FIXTURE.exists():
        raise SystemExit(f"PDF fixture not found: {FIXTURE}")

    session = requests.Session()

    password = getpass.getpass("Administrator password: ")

    login = session.post(
        f"{BASE_URL}/api/v1/auth/login",
        json={"username": "admin", "password": password},
        timeout=15,
    )

    print("Login HTTP status:", login.status_code)
    login.raise_for_status()

    csrf_token = login.json().get("csrf_token")
    if not csrf_token:
        raise SystemExit("CSRF token missing from login response")

    headers = {"X-CSRF-Token": csrf_token}

    with FIXTURE.open("rb") as pdf:
        response = session.post(
            f"{BASE_URL}/api/v1/documents",
            headers=headers,
            files={"file": ("demo_document.pdf", pdf, "application/pdf")},
            timeout=60,
        )

    print("Upload HTTP status:", response.status_code)
    print("Response:", response.text)

    response.raise_for_status()

    data = response.json()
    document_id = data.get("id") or data.get("document_id")

    print("\nUpload successful.")
    print("Document ID:", document_id)
    print("Original SHA-256:", hashlib.sha256(FIXTURE.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
