import getpass

import requests

BASE_URL = "http://127.0.0.1:8000"
DOCUMENT_ID = "b2b4c080-f986-42b8-bcc5-6a85b1fa70e6"


def main():
    session = requests.Session()

    password = getpass.getpass("demo_viewer password: ")

    login = session.post(
        f"{BASE_URL}/api/v1/auth/login",
        json={"username": "demo_viewer", "password": password},
        timeout=15,
    )

    print("Login HTTP status:", login.status_code)
    login.raise_for_status()

    user = login.json().get("user", {})
    print("Authenticated user:", user.get("username", "demo_viewer"))
    print("Role:", user.get("role", "user"))

    response = session.get(
        f"{BASE_URL}/api/v1/documents/{DOCUMENT_ID}/download",
        timeout=30,
    )

    print("\nUnauthorized download test")
    print("HTTP status:", response.status_code)
    print("Response:", response.text)

    if response.status_code == 404:
        print("\nPASS: Unauthorized document access was denied.")
    else:
        raise SystemExit(
            f"FAIL: Expected HTTP 404, received {response.status_code}"
        )


if __name__ == "__main__":
    main()
