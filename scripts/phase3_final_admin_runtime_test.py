"""Exercise the final-active-administrator API safeguards.

Usage (with the API running on loopback and HTTPX installed)::

    python3 scripts/phase3_final_admin_runtime_test.py

This is a destructive-regression probe: if either final-admin guard is broken,
the API could change the existing administrator being tested. Run it only on a
dedicated isolated test instance, never on production or the only copy of
important data. The script requires an explicit isolation confirmation before
it sends any request.

It creates one uniquely named temporary administrator, deactivates that
temporary account, tests deactivation and demotion of the original sole
administrator, and attempts cleanup in a finally block. It never deletes
records. Credentials, cookies, and CSRF tokens remain in memory and are never
printed or written to disk. Redirects are not followed.
"""

from __future__ import annotations

import getpass
import secrets
import sys
import unicodedata
import uuid
from typing import Any

import httpx

BASE_URL = "http://127.0.0.1:8000"
COOKIE_NAME = "docvault_session"
SAFE_USER_FIELDS = {
    "id",
    "username",
    "role",
    "is_active",
    "created_at",
    "updated_at",
}
ISOLATION_CONFIRMATION = "RUN ON ISOLATED TEST INSTANCE"

_results: list[bool] = []


def report(name: str, expected: int, actual: int | str, passed: bool) -> None:
    """Print only the test name, expected/actual status, and result."""
    print(f"{name}: expected={expected} actual={actual} {'PASS' if passed else 'FAIL'}")
    _results.append(passed)


def skipped(name: str, expected: int) -> None:
    report(name, expected, "NOT_RUN", False)


def get_status(
    response_call: Any,
) -> tuple[httpx.Response | None, int | str]:
    """Make one request without printing response content or exceptions."""
    try:
        response = response_call()
    except httpx.RequestError:
        return None, "NO_RESPONSE"
    return response, response.status_code


def decode_object(response: httpx.Response | None) -> dict[str, Any]:
    if response is None:
        return {}
    try:
        value = response.json()
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def safe_user(
    value: Any,
    username: str,
    *,
    role: str,
    active: bool,
) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == SAFE_USER_FIELDS
        and value.get("username") == username
        and value.get("role") == role
        and value.get("is_active") is active
    )


def listed_users(response: httpx.Response | None) -> list[dict[str, Any]] | None:
    if response is None:
        return None
    try:
        value = response.json()
    except ValueError:
        return None
    if not isinstance(value, list) or any(
        not isinstance(user, dict) or set(user) != SAFE_USER_FIELDS for user in value
    ):
        return None
    return value


def active_admin_ids(users: list[dict[str, Any]]) -> list[str]:
    return [
        str(user["id"])
        for user in users
        if user.get("role") == "administrator" and user.get("is_active") is True
    ]


def main() -> int:
    if not sys.stdin.isatty():
        report("interactive_confirmation_required", 200, "NO_TTY", False)
        return 1

    confirmation = input(
        f"Type '{ISOLATION_CONFIRMATION}' to continue: "
    )
    if confirmation != ISOLATION_CONFIRMATION:
        report("isolated_instance_confirmation", 200, "NOT_CONFIRMED", False)
        return 1

    username = ""
    while not username:
        username = input("Existing administrator username: ").strip()
    password = getpass.getpass("Administrator password: ")
    normalized_username = unicodedata.normalize("NFKC", username).strip().casefold()

    client = httpx.Client(
        base_url=BASE_URL,
        timeout=10.0,
        follow_redirects=False,
        trust_env=False,
    )
    admin_csrf: str | None = None
    original_id: str | None = None
    original_authenticated = False
    temp_username: str | None = None
    temp_password: str | None = None
    temp_user_id: uuid.UUID | None = None
    temp_creation_may_have_committed = False
    temp_creation_known_failed = False

    try:
        try:
            login_response, login_status = get_status(
                lambda: client.post(
                    "/api/v1/auth/login",
                    json={"username": username, "password": password},
                )
            )
            login_body = decode_object(login_response if login_status == 200 else None)
            admin_user = login_body.get("user")
            admin_csrf = login_body.get("csrf_token")
            if isinstance(admin_user, dict) and admin_user.get("id") is not None:
                original_id = str(admin_user["id"])
            admin_login_ok = (
                login_status == 200
                and safe_user(
                    admin_user,
                    normalized_username,
                    role="administrator",
                    active=True,
                )
                and isinstance(admin_csrf, str)
                and bool(admin_csrf)
                and original_id is not None
            )
            original_authenticated = admin_login_ok
            report("existing_administrator_login", 200, login_status, admin_login_ok)

            if not admin_login_ok or original_id is None:
                skipped("original_is_only_active_administrator", 200)
                skipped("temporary_administrator_created", 201)
                skipped("temporary_administrator_deactivated", 200)
                skipped("original_deactivation_rejected", 409)
                skipped("original_demotion_rejected", 409)
            else:
                users_response, preflight_status = get_status(
                    lambda: client.get("/api/v1/admin/users")
                )
                users = listed_users(users_response)
                initial_only_admin = (
                    users is not None
                    and active_admin_ids(users) == [original_id]
                    and any(
                        user.get("id") == original_id
                        and user.get("username") == normalized_username
                        and user.get("role") == "administrator"
                        and user.get("is_active") is True
                        for user in users
                    )
                )
                report(
                    "original_is_only_active_administrator",
                    200,
                    preflight_status,
                    preflight_status == 200 and initial_only_admin,
                )

                if not initial_only_admin or users is None:
                    skipped("temporary_administrator_created", 201)
                    skipped("temporary_administrator_deactivated", 200)
                    skipped("original_deactivation_rejected", 409)
                    skipped("original_demotion_rejected", 409)
                else:
                    existing_names = {str(user.get("username")) for user in users}
                    for _attempt in range(5):
                        candidate = f"rtadm_{secrets.token_hex(12)}"
                        if candidate not in existing_names:
                            temp_username = candidate
                            break

                    if temp_username is None:
                        report("temporary_username_available", 200, 200, False)
                        skipped("temporary_administrator_created", 201)
                        skipped("temporary_administrator_deactivated", 200)
                        skipped("original_deactivation_rejected", 409)
                        skipped("original_demotion_rejected", 409)
                    else:
                        report("temporary_username_available", 200, 200, True)
                        temp_password = secrets.token_urlsafe(24) + "Aa1!"
                        create_payload = {
                            "username": temp_username,
                            "password": temp_password,
                            "role": "administrator",
                        }
                        temp_creation_may_have_committed = True
                        create_response, create_status = get_status(
                            lambda: client.post(
                                "/api/v1/admin/users",
                                json=create_payload,
                                headers={"X-CSRF-Token": admin_csrf},
                            )
                        )
                        if create_status in {400, 401, 403, 404, 409, 422, 429}:
                            temp_creation_may_have_committed = False
                            temp_creation_known_failed = True

                        created_user = decode_object(
                            create_response if create_status == 201 else None
                        )
                        try:
                            if created_user.get("id") is not None:
                                temp_user_id = uuid.UUID(str(created_user["id"]))
                        except (ValueError, TypeError, AttributeError):
                            temp_user_id = None
                        create_ok = (
                            create_status == 201
                            and safe_user(
                                created_user,
                                temp_username,
                                role="administrator",
                                active=True,
                            )
                            and temp_user_id is not None
                        )
                        report(
                            "temporary_administrator_created",
                            201,
                            create_status,
                            create_ok,
                        )

                        if not create_ok or temp_user_id is None:
                            skipped("temporary_administrator_deactivated", 200)
                            skipped("original_deactivation_rejected", 409)
                            skipped("original_demotion_rejected", 409)
                        else:
                            deactivate_response, deactivate_status = get_status(
                                lambda: client.patch(
                                    f"/api/v1/admin/users/{temp_user_id}/status",
                                    json={"is_active": False},
                                    headers={"X-CSRF-Token": admin_csrf},
                                )
                            )
                            temp_deactivated = (
                                deactivate_status == 200
                                and safe_user(
                                    decode_object(deactivate_response),
                                    temp_username,
                                    role="administrator",
                                    active=False,
                                )
                            )
                            report(
                                "temporary_administrator_deactivated",
                                200,
                                deactivate_status,
                                temp_deactivated,
                            )

                            if temp_deactivated:
                                verification_response, verification_status = get_status(
                                    lambda: client.get("/api/v1/admin/users")
                                )
                                verified_users = listed_users(verification_response)
                                sole_original_remains = (
                                    verified_users is not None
                                    and active_admin_ids(verified_users) == [original_id]
                                )
                                report(
                                    "original_is_only_active_administrator_after_setup",
                                    200,
                                    verification_status,
                                    verification_status == 200 and sole_original_remains,
                                )

                                if sole_original_remains:
                                    status_response, status_code = get_status(
                                        lambda: client.patch(
                                            f"/api/v1/admin/users/{original_id}/status",
                                            json={"is_active": False},
                                            headers={"X-CSRF-Token": admin_csrf},
                                        )
                                    )
                                    status_detail = decode_object(status_response).get("detail")
                                    report(
                                        "original_deactivation_rejected",
                                        409,
                                        status_code,
                                        status_code == 409
                                        and status_detail
                                        == "The final active administrator cannot be deactivated",
                                    )

                                    role_response, role_status = get_status(
                                        lambda: client.patch(
                                            f"/api/v1/admin/users/{original_id}/role",
                                            json={"role": "user"},
                                            headers={"X-CSRF-Token": admin_csrf},
                                        )
                                    )
                                    role_detail = decode_object(role_response).get("detail")
                                    report(
                                        "original_demotion_rejected",
                                        409,
                                        role_status,
                                        role_status == 409
                                        and role_detail
                                        == "The final active administrator cannot be demoted",
                                    )
                                else:
                                    skipped("original_deactivation_rejected", 409)
                                    skipped("original_demotion_rejected", 409)
                            else:
                                skipped("original_deactivation_rejected", 409)
                                skipped("original_demotion_rejected", 409)
        except Exception:  # noqa: BLE001 - keep secrets out of tracebacks and run finally cleanup
            report("runtime_sequence_unexpected_error", 200, "ERROR", False)
    finally:
        if temp_creation_may_have_committed and temp_username is not None:
            cleanup_status: int | str = "NO_RESPONSE"
            cleanup_ok = False
            try:
                lookup_response, lookup_status = get_status(
                    lambda: client.get("/api/v1/admin/users")
                )
                lookup_users = listed_users(lookup_response)
                matching = (
                    [
                        user
                        for user in lookup_users
                        if user.get("username") == temp_username
                    ]
                    if lookup_users is not None
                    else []
                )
                cleanup_user_id: uuid.UUID | None = None
                if len(matching) == 1:
                    try:
                        candidate_id = uuid.UUID(str(matching[0].get("id")))
                        if temp_user_id is None or candidate_id == temp_user_id:
                            cleanup_user_id = candidate_id
                        else:
                            cleanup_status = "IDENTITY_MISMATCH"
                    except (ValueError, TypeError, AttributeError):
                        cleanup_status = "INVALID_ID"
                elif lookup_status == 200:
                    cleanup_status = "NOT_FOUND"
                else:
                    cleanup_status = lookup_status

                if cleanup_user_id is not None and isinstance(admin_csrf, str):
                    cleanup_response, cleanup_status = get_status(
                        lambda: client.patch(
                            f"/api/v1/admin/users/{cleanup_user_id}/status",
                            json={"is_active": False},
                            headers={"X-CSRF-Token": admin_csrf},
                        )
                    )
                    cleanup_ok = (
                        cleanup_status == 200
                        and safe_user(
                            decode_object(cleanup_response),
                            temp_username,
                            role="administrator",
                            active=False,
                        )
                    )
            except Exception:  # noqa: BLE001 - expose cleanup failure without details
                cleanup_status = "ERROR"
                cleanup_ok = False

            if cleanup_ok:
                report("temporary_administrator_cleanup", 200, cleanup_status, True)
            else:
                report(
                    "cleanup_failed_temporary_administrator_may_remain_active",
                    200,
                    cleanup_status,
                    False,
                )
        elif temp_creation_known_failed:
            report("temporary_administrator_cleanup", 200, "NOT_NEEDED", True)

        if original_authenticated:
            original_response, original_status = get_status(
                lambda: client.get("/api/v1/auth/me")
            )
            original_body = decode_object(original_response if original_status == 200 else None)
            original_preserved = safe_user(
                original_body,
                normalized_username,
                role="administrator",
                active=True,
            )
            report(
                "original_administrator_remains_active_and_administrator",
                200,
                original_status,
                original_status == 200 and original_preserved,
            )

            if isinstance(admin_csrf, str) and admin_csrf:
                _logout_response, logout_status = get_status(
                    lambda: client.post(
                        "/api/v1/auth/logout",
                        headers={"X-CSRF-Token": admin_csrf},
                    )
                )
                report("administrator_session_logout", 204, logout_status, logout_status == 204)

        client.close()

    return 0 if all(_results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
