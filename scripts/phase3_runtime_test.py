"""Safely exercise the live Phase 3 cookie-authentication HTTP endpoints.

Usage (with the API running on loopback and HTTPX installed)::

    python3 scripts/phase3_runtime_test.py

Enter an existing administrator username and password when prompted. The
script makes an intentional failed login attempt (which counts toward login
throttling), runs an administrator authentication sequence, then creates one
temporary ordinary account and deactivates it during cleanup. It does not
change any pre-existing account. Successful logins create server-side sessions
that the test revokes by logout or account deactivation.

For this loopback HTTP test, configure the API with AUTH_COOKIE_SECURE=false.
Use it only on the trusted local host; HTTPS deployments should retain Secure
cookies and use a separate HTTPS test client configuration.

Only test names and status results are printed. Passwords, cookies, CSRF
tokens, response bodies, and Set-Cookie headers remain in memory and are never
printed or written to disk. Redirects are not followed.
"""

from __future__ import annotations

import getpass
import secrets
import sys
import unicodedata
import uuid
from http.cookies import SimpleCookie
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

_results: list[bool] = []


def report(name: str, expected: int, actual: int | str, passed: bool) -> None:
    """Print only the test label, expected/actual status, and result."""
    outcome = "PASS" if passed else "FAIL"
    print(f"{name}: expected={expected} actual={actual} {outcome}")
    _results.append(passed)


def skipped(name: str, expected: int) -> None:
    """Record dependent checks that cannot run without a valid login."""
    report(name, expected, "NOT_RUN", False)


def get_status(response_call: Any) -> tuple[httpx.Response | None, int | str]:
    """Run a request without exposing exception or response content."""
    try:
        response = response_call()
    except httpx.RequestError:
        return None, "NO_RESPONSE"
    return response, response.status_code


def is_safe_user(value: Any, expected_username: str) -> bool:
    if not isinstance(value, dict) or set(value) != SAFE_USER_FIELDS:
        return False
    return (
        value.get("username") == expected_username
        and value.get("role") == "administrator"
        and value.get("is_active") is True
    )


def is_safe_profile(
    value: Any,
    expected_username: str,
    expected_role: str,
    *,
    expected_active: bool = True,
) -> bool:
    if not isinstance(value, dict) or set(value) != SAFE_USER_FIELDS:
        return False
    return (
        value.get("username") == expected_username
        and value.get("role") == expected_role
        and value.get("is_active") is expected_active
    )


def response_has_no_sensitive_data(
    response: httpx.Response,
    sensitive_values: tuple[str, ...],
) -> bool:
    """Check a response in memory without exposing it in test output."""
    body = response.content
    lowered_body = body.lower()
    forbidden_markers = (
        b"password_hash",
        b"session_token",
        b"session_id",
        b"csrf_token_hash",
        b"auth_session",
        b'"sessions"',
    )
    if any(marker in lowered_body for marker in forbidden_markers):
        return False
    if any(value and value.encode("utf-8") in body for value in sensitive_values):
        return False
    return not any(name.lower() == "set-cookie" for name, _value in response.headers.multi_items())


def run_user_management_sequence(username: str, password: str) -> None:
    """Create, authorize-test, and finally deactivate one temporary user."""
    normalized_admin = unicodedata.normalize("NFKC", username).strip().casefold()
    admin_client = httpx.Client(
        base_url=BASE_URL,
        timeout=10.0,
        follow_redirects=False,
        trust_env=False,
    )
    ordinary_client = httpx.Client(
        base_url=BASE_URL,
        timeout=10.0,
        follow_redirects=False,
        trust_env=False,
    )

    temp_username: str | None = None
    temp_password: str | None = None
    temp_user_id: uuid.UUID | None = None
    ordinary_csrf: str | None = None
    ordinary_session_cookie: str | None = None
    admin_csrf: str | None = None
    creation_may_have_committed = False

    def skip_user_checks() -> None:
        skipped("temporary_username_available", 200)
        skipped("temporary_user_created", 201)
        skipped("duplicate_temporary_user_rejected", 409)
        skipped("ordinary_user_login", 200)
        skipped("ordinary_user_me", 200)
        skipped("ordinary_user_admin_list_denied", 403)
        skipped("ordinary_user_admin_create_denied", 403)
        skipped("ordinary_user_admin_status_denied", 403)
        skipped("ordinary_user_admin_role_denied", 403)
        skipped("ordinary_responses_exclude_password_hashes_and_sessions", 200)

    try:
        try:
            admin_login_response, admin_login_status = get_status(
                lambda: admin_client.post(
                    "/api/v1/auth/login",
                    json={"username": username, "password": password},
                )
            )
            admin_login_body: dict[str, Any] = {}
            if admin_login_response is not None and admin_login_status == 200:
                try:
                    decoded = admin_login_response.json()
                    if isinstance(decoded, dict):
                        admin_login_body = decoded
                except ValueError:
                    pass
            admin_csrf = admin_login_body.get("csrf_token")
            admin_login_ok = (
                admin_login_status == 200
                and is_safe_user(admin_login_body.get("user"), normalized_admin)
                and isinstance(admin_csrf, str)
                and bool(admin_csrf)
            )
            report("management_admin_login", 200, admin_login_status, admin_login_ok)
            if not admin_login_ok:
                skip_user_checks()
                skipped("temporary_account_cleanup", 200)
                skipped("deactivated_user_session_rejected", 401)
                return

            # Generate a valid, high-entropy username and verify it is absent
            # before attempting creation, so cleanup cannot target an existing
            # account that happened to share the generated name.
            existing_users_response, preflight_status = get_status(
                lambda: admin_client.get("/api/v1/admin/users")
            )
            existing_users: list[Any] = []
            preflight_ok = False
            if existing_users_response is not None and preflight_status == 200:
                try:
                    decoded_users = existing_users_response.json()
                    if isinstance(decoded_users, list) and all(
                        isinstance(item, dict) and set(item) == SAFE_USER_FIELDS
                        for item in decoded_users
                    ):
                        existing_users = decoded_users
                        preflight_ok = True
                except (ValueError, TypeError):
                    preflight_ok = False

            existing_names = {
                str(item.get("username")) for item in existing_users if isinstance(item, dict)
            }
            if preflight_ok:
                for _attempt in range(5):
                    candidate = f"rt_user_{secrets.token_hex(12)}"
                    if candidate not in existing_names:
                        temp_username = candidate
                        break
            preflight_ok = preflight_ok and temp_username is not None
            report(
                "temporary_username_available",
                200,
                preflight_status,
                preflight_status == 200 and preflight_ok,
            )
            if not preflight_ok or temp_username is None:
                skip_user_checks_after_preflight()
                skipped("temporary_account_cleanup", 200)
                skipped("deactivated_user_session_rejected", 401)
                return

            # The suffix guarantees lower, upper, digit, and punctuation
            # categories in addition to the random URL-safe password material.
            temp_password = secrets.token_urlsafe(24) + "Aa1!"
            create_payload = {
                "username": temp_username,
                "password": temp_password,
                "role": "user",
            }
            creation_may_have_committed = True
            create_response, create_status = get_status(
                lambda: admin_client.post(
                    "/api/v1/admin/users",
                    json=create_payload,
                    headers={"X-CSRF-Token": admin_csrf},
                )
            )
            if create_status in {400, 401, 403, 404, 409, 422, 429}:
                creation_may_have_committed = False

            created_user: Any = None
            if create_response is not None and create_status == 201:
                try:
                    created_user = create_response.json()
                    if isinstance(created_user, dict):
                        temp_user_id = uuid.UUID(str(created_user.get("id")))
                except (ValueError, TypeError, AttributeError):
                    temp_user_id = None
            create_ok = (
                create_status == 201
                and is_safe_profile(created_user, temp_username, "user")
            )
            report("temporary_user_created", 201, create_status, create_ok)
            if create_status != 201:
                skip_user_checks_after_creation()
                if not creation_may_have_committed:
                    report("temporary_account_cleanup", 200, "NOT_NEEDED", True)
                    skipped("deactivated_user_session_rejected", 401)
                return

            duplicate_response, duplicate_status = get_status(
                lambda: admin_client.post(
                    "/api/v1/admin/users",
                    json=create_payload,
                    headers={"X-CSRF-Token": admin_csrf},
                )
            )
            duplicate_safe = (
                duplicate_response is not None
                and response_has_no_sensitive_data(
                    duplicate_response,
                    (password, temp_password, admin_csrf),
                )
            )
            report(
                "duplicate_temporary_user_rejected",
                409,
                duplicate_status,
                duplicate_status == 409 and duplicate_safe,
            )

            ordinary_login_response, ordinary_login_status = get_status(
                lambda: ordinary_client.post(
                    "/api/v1/auth/login",
                    json={"username": temp_username, "password": temp_password},
                )
            )
            ordinary_login_body: dict[str, Any] = {}
            if ordinary_login_response is not None and ordinary_login_status == 200:
                try:
                    decoded = ordinary_login_response.json()
                    if isinstance(decoded, dict):
                        ordinary_login_body = decoded
                except ValueError:
                    pass
            ordinary_csrf = ordinary_login_body.get("csrf_token")
            ordinary_session_cookie = (
                ordinary_login_response.cookies.get(COOKIE_NAME)
                if ordinary_login_response is not None
                else None
            )
            ordinary_login_ok = (
                ordinary_login_status == 200
                and set(ordinary_login_body) == {"user", "csrf_token"}
                and is_safe_profile(
                    ordinary_login_body.get("user"), temp_username, "user"
                )
                and isinstance(ordinary_csrf, str)
                and bool(ordinary_csrf)
                and bool(ordinary_session_cookie)
            )
            report(
                "ordinary_user_login",
                200,
                ordinary_login_status,
                ordinary_login_ok,
            )

            if ordinary_login_status != 200 or not isinstance(ordinary_csrf, str):
                skipped("ordinary_user_me", 200)
                skipped("ordinary_user_admin_list_denied", 403)
                skipped("ordinary_user_admin_create_denied", 403)
                skipped("ordinary_user_admin_status_denied", 403)
                skipped("ordinary_user_admin_role_denied", 403)
                skipped("ordinary_responses_exclude_password_hashes_and_sessions", 200)
                return

            sensitive_values = (
                password,
                temp_password,
                str(admin_csrf),
                ordinary_csrf,
                ordinary_session_cookie or "",
            )
            ordinary_responses_safe = [ordinary_login_ok]

            me_response, me_status = get_status(
                lambda: ordinary_client.get("/api/v1/auth/me")
            )
            me_safe = False
            if me_response is not None and me_status == 200:
                try:
                    me_safe = is_safe_profile(
                        me_response.json(), temp_username, "user"
                    )
                except (ValueError, AttributeError):
                    me_safe = False
            ordinary_responses_safe.append(me_safe)
            report("ordinary_user_me", 200, me_status, me_status == 200 and me_safe)

            denied_response, denied_status = get_status(
                lambda: ordinary_client.get("/api/v1/admin/users")
            )
            denial_safe = denied_response is not None and response_has_no_sensitive_data(
                denied_response, sensitive_values
            )
            ordinary_responses_safe.append(denial_safe)
            report(
                "ordinary_user_admin_list_denied",
                403,
                denied_status,
                denied_status == 403 and denial_safe,
            )

            # Reuse the temporary identity for POST so an authorization bug
            # would hit duplicate-identity protection (409), not create a
            # second account or grant privileges.
            denied_response, denied_status = get_status(
                lambda: ordinary_client.post(
                    "/api/v1/admin/users",
                    json={
                        "username": temp_username,
                        "password": temp_password,
                        "role": "administrator",
                    },
                    headers={"X-CSRF-Token": ordinary_csrf},
                )
            )
            denial_safe = denied_response is not None and response_has_no_sensitive_data(
                denied_response, sensitive_values
            )
            ordinary_responses_safe.append(denial_safe)
            report(
                "ordinary_user_admin_create_denied",
                403,
                denied_status,
                denied_status == 403 and denial_safe,
            )

            # The status and role payloads are no-ops for this temporary user,
            # so a broken authorization check cannot affect a pre-existing user
            # or retain any elevated role.
            denied_response, denied_status = get_status(
                lambda: ordinary_client.patch(
                    f"/api/v1/admin/users/{temp_user_id}/status",
                    json={"is_active": True},
                    headers={"X-CSRF-Token": ordinary_csrf},
                )
            )
            denial_safe = denied_response is not None and response_has_no_sensitive_data(
                denied_response, sensitive_values
            )
            ordinary_responses_safe.append(denial_safe)
            report(
                "ordinary_user_admin_status_denied",
                403,
                denied_status,
                denied_status == 403 and denial_safe,
            )

            denied_response, denied_status = get_status(
                lambda: ordinary_client.patch(
                    f"/api/v1/admin/users/{temp_user_id}/role",
                    json={"role": "user"},
                    headers={"X-CSRF-Token": ordinary_csrf},
                )
            )
            denial_safe = denied_response is not None and response_has_no_sensitive_data(
                denied_response, sensitive_values
            )
            ordinary_responses_safe.append(denial_safe)
            report(
                "ordinary_user_admin_role_denied",
                403,
                denied_status,
                denied_status == 403 and denial_safe,
            )
            report(
                "ordinary_responses_exclude_password_hashes_and_sessions",
                200,
                me_status,
                me_status == 200 and all(ordinary_responses_safe),
            )
        except Exception:  # noqa: BLE001 - preserve the guaranteed cleanup path
            # Do not expose an exception that might contain request details.
            # The finally block below still attempts account cleanup.
            report("management_sequence_unexpected_error", 200, "ERROR", False)
    finally:
        if creation_may_have_committed and temp_username is not None:
            cleanup_status: int | str = "NO_RESPONSE"
            cleanup_ok = False
            try:
                # Resolve the generated name again before changing status, and
                # require it to match the ID returned at creation when one was
                # received. This avoids acting on another account if a response
                # was malformed or the create request outcome was uncertain.
                cleanup_lookup_status: int | str = "NO_RESPONSE"
                lookup_response, cleanup_lookup_status = get_status(
                    lambda: admin_client.get("/api/v1/admin/users")
                )
                cleanup_user_id: uuid.UUID | None = None
                if lookup_response is not None and cleanup_lookup_status == 200:
                    try:
                        lookup_users = lookup_response.json()
                        matching = (
                            [
                                item
                                for item in lookup_users
                                if isinstance(item, dict)
                                and item.get("username") == temp_username
                            ]
                            if isinstance(lookup_users, list)
                            else []
                        )
                        if len(matching) == 1:
                            candidate_id = uuid.UUID(str(matching[0].get("id")))
                            if temp_user_id is None or candidate_id == temp_user_id:
                                cleanup_user_id = candidate_id
                            else:
                                cleanup_status = "IDENTITY_MISMATCH"
                    except (ValueError, TypeError, AttributeError):
                        cleanup_user_id = None
                elif cleanup_lookup_status != 200:
                    cleanup_status = cleanup_lookup_status

                if cleanup_user_id is not None and isinstance(admin_csrf, str):
                    cleanup_response, cleanup_status = get_status(
                        lambda: admin_client.patch(
                            f"/api/v1/admin/users/{cleanup_user_id}/status",
                            json={"is_active": False},
                            headers={"X-CSRF-Token": admin_csrf},
                        )
                    )
                    if cleanup_response is not None and cleanup_status == 200:
                        try:
                            cleanup_ok = is_safe_profile(
                                cleanup_response.json(),
                                temp_username,
                                "user",
                                expected_active=False,
                            )
                        except (ValueError, AttributeError):
                            cleanup_ok = False
                elif cleanup_lookup_status == 200 and cleanup_status != "IDENTITY_MISMATCH":
                    cleanup_status = "NOT_FOUND"
                elif cleanup_lookup_status != "NOT_NEEDED":
                    cleanup_status = cleanup_lookup_status
            except Exception:  # noqa: BLE001 - always report cleanup failure without exposing details
                cleanup_status = "ERROR"
                cleanup_ok = False

            if cleanup_ok:
                report("temporary_account_cleanup", 200, cleanup_status, True)
            else:
                report(
                    "cleanup_failed_temp_account_may_remain_active",
                    200,
                    cleanup_status,
                    False,
                )

            if ordinary_session_cookie:
                replay_response, replay_status = get_status(
                    lambda: ordinary_client.get(
                        "/api/v1/auth/me",
                        headers={
                            "Cookie": f"{COOKIE_NAME}={ordinary_session_cookie}"
                        },
                    )
                )
                safe_rejection = (
                    replay_response is not None
                    and response_has_no_sensitive_data(
                        replay_response,
                        (
                            password,
                            temp_password or "",
                            ordinary_csrf or "",
                            ordinary_session_cookie,
                        ),
                    )
                )
                report(
                    "deactivated_user_session_rejected",
                    401,
                    replay_status,
                    replay_status == 401 and safe_rejection,
                )
            else:
                skipped("deactivated_user_session_rejected", 401)

        if isinstance(admin_csrf, str) and admin_csrf:
            _admin_logout_response, admin_logout_status = get_status(
                lambda: admin_client.post(
                    "/api/v1/auth/logout",
                    headers={"X-CSRF-Token": admin_csrf},
                )
            )
            report(
                "management_admin_logout",
                204,
                admin_logout_status,
                admin_logout_status == 204,
            )
        elif admin_client.cookies.get(COOKIE_NAME):
            report("management_admin_logout", 204, "NO_CSRF", False)
        else:
            report("management_admin_logout", 204, "NOT_NEEDED", True)

        admin_client.close()
        ordinary_client.close()


def skip_user_checks_after_preflight() -> None:
    skipped("temporary_user_created", 201)
    skipped("duplicate_temporary_user_rejected", 409)
    skipped("ordinary_user_login", 200)
    skipped("ordinary_user_me", 200)
    skipped("ordinary_user_admin_list_denied", 403)
    skipped("ordinary_user_admin_create_denied", 403)
    skipped("ordinary_user_admin_status_denied", 403)
    skipped("ordinary_user_admin_role_denied", 403)
    skipped("ordinary_responses_exclude_password_hashes_and_sessions", 200)


def skip_user_checks_after_creation() -> None:
    skipped("duplicate_temporary_user_rejected", 409)
    skipped("ordinary_user_login", 200)
    skipped("ordinary_user_me", 200)
    skipped("ordinary_user_admin_list_denied", 403)
    skipped("ordinary_user_admin_create_denied", 403)
    skipped("ordinary_user_admin_status_denied", 403)
    skipped("ordinary_user_admin_role_denied", 403)
    skipped("ordinary_responses_exclude_password_hashes_and_sessions", 200)


def main() -> int:
    if not sys.stdin.isatty():
        report("interactive_terminal_required", 200, "NO_TTY", False)
        return 1

    username = ""
    while not username:
        username = input("Administrator username: ").strip()
    password = getpass.getpass("Administrator password: ")

    normalized_username = unicodedata.normalize("NFKC", username).strip().casefold()
    # Use a generated wrong password so no actual credential is reused for the
    # negative-login check. The failed attempt is still subject to throttling.
    invalid_password = secrets.token_urlsafe(24)

    # trust_env=False avoids routing loopback requests through proxy variables.
    # follow_redirects=False ensures redirects are reported as failures.
    with httpx.Client(
        base_url=BASE_URL,
        timeout=10.0,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        _unauth_response, unauth_status = get_status(
            lambda: client.get("/api/v1/auth/me")
        )
        report(
            "unauthenticated_current_user",
            401,
            unauth_status,
            unauth_status == 401,
        )

        invalid_response, invalid_status = get_status(
            lambda: client.post(
                "/api/v1/auth/login",
                json={"username": username, "password": invalid_password},
            )
        )
        generic_failure = False
        if invalid_response is not None and invalid_status == 401:
            try:
                generic_failure = (
                    invalid_response.json().get("detail")
                    == "Invalid username or password"
                )
            except (ValueError, AttributeError):
                generic_failure = False
        report(
            "invalid_login_generic_failure",
            401,
            invalid_status,
            invalid_status == 401 and generic_failure,
        )

        login_response, login_status = get_status(
            lambda: client.post(
                "/api/v1/auth/login",
                json={"username": username, "password": password},
            )
        )
        login_body: dict[str, Any] = {}
        if login_response is not None and login_status == 200:
            try:
                decoded = login_response.json()
                if isinstance(decoded, dict):
                    login_body = decoded
            except ValueError:
                pass
        user_data = login_body.get("user")
        user_ok = is_safe_user(user_data, normalized_username)
        csrf_token = login_body.get("csrf_token")
        csrf_ok = isinstance(csrf_token, str) and bool(csrf_token)
        login_ok = login_status == 200 and user_ok and csrf_ok
        report(
            "valid_administrator_login_and_safe_user_schema",
            200,
            login_status,
            login_ok,
        )

        cookie_attributes_ok = False
        session_cookie: str | None = None
        if login_response is not None and login_status == 200:
            try:
                parsed_cookies = SimpleCookie()
                for header in login_response.headers.get_list("set-cookie"):
                    parsed_cookies.load(header)
                morsel = parsed_cookies.get(COOKIE_NAME)
                if morsel is not None:
                    cookie_attributes_ok = (
                        bool(morsel["httponly"])
                        and morsel["samesite"].lower() == "lax"
                        and morsel["path"] == "/api/v1"
                    )
                session_cookie = login_response.cookies.get(COOKIE_NAME)
            except (KeyError, TypeError, ValueError):
                cookie_attributes_ok = False
        report(
            "session_cookie_attributes",
            200,
            login_status,
            login_status == 200 and cookie_attributes_ok and bool(session_cookie),
        )

        if login_status != 200 or not user_ok or not csrf_ok:
            skipped("authenticated_current_user", 200)
            skipped("administrator_user_list", 200)
            skipped("logout_without_csrf", 403)
            skipped("session_valid_after_csrf_rejection", 200)
            skipped("logout_with_csrf", 204)
            skipped("revoked_session_replay", 401)
            return 1

        me_response, me_status = get_status(
            lambda: client.get("/api/v1/auth/me")
        )
        me_ok = False
        if me_response is not None and me_status == 200:
            try:
                me_ok = is_safe_user(me_response.json(), normalized_username)
            except (ValueError, AttributeError):
                me_ok = False
        report("authenticated_current_user", 200, me_status, me_status == 200 and me_ok)

        users_response, users_status = get_status(
            lambda: client.get("/api/v1/admin/users")
        )
        users_ok = False
        if users_response is not None and users_status == 200:
            try:
                users = users_response.json()
                users_ok = isinstance(users, list) and all(
                    isinstance(user, dict) and set(user) == SAFE_USER_FIELDS
                    for user in users
                )
            except (ValueError, TypeError):
                users_ok = False
        report("administrator_user_list", 200, users_status, users_status == 200 and users_ok)

        _no_csrf_response, no_csrf_status = get_status(
            lambda: client.post("/api/v1/auth/logout")
        )
        report("logout_without_csrf", 403, no_csrf_status, no_csrf_status == 403)

        _still_valid_response, still_valid_status = get_status(
            lambda: client.get("/api/v1/auth/me")
        )
        report(
            "session_valid_after_csrf_rejection",
            200,
            still_valid_status,
            still_valid_status == 200,
        )

        _logout_response, logout_status = get_status(
            lambda: client.post(
                "/api/v1/auth/logout",
                headers={"X-CSRF-Token": csrf_token},
            )
        )
        report("logout_with_csrf", 204, logout_status, logout_status == 204)

        replay_status: int | str = "NO_RESPONSE"
        if session_cookie:
            with httpx.Client(
                base_url=BASE_URL,
                timeout=10.0,
                follow_redirects=False,
                trust_env=False,
            ) as replay_client:
                _replay_response, replay_status = get_status(
                    lambda: replay_client.get(
                        "/api/v1/auth/me",
                        headers={"Cookie": f"{COOKIE_NAME}={session_cookie}"},
                    )
                )
        report("revoked_session_replay", 401, replay_status, replay_status == 401)

    run_user_management_sequence(username, password)
    return 0 if all(_results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
