"""Interactive application-administrator bootstrap command."""

import argparse
import getpass
import sys

from sqlalchemy.exc import SQLAlchemyError

from app.db.session import get_session_factory
from app.security.passwords import PasswordPolicyError, validate_password
from app.services.users import InitialAdminExistsError, bootstrap_first_admin


def bootstrap_admin() -> int:
    if not sys.stdin.isatty():
        print("Administrator bootstrap requires an interactive terminal", file=sys.stderr)
        return 2
    username = input("Administrator username: ")
    password = getpass.getpass("Administrator password: ")
    confirmation = getpass.getpass("Confirm administrator password: ")
    if password != confirmation:
        print("Passwords did not match", file=sys.stderr)
        return 2
    try:
        validate_password(password)
    except PasswordPolicyError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    db = get_session_factory()()
    try:
        user = bootstrap_first_admin(db, username, password)
    except InitialAdminExistsError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (ValueError, SQLAlchemyError) as exc:
        db.rollback()
        message = str(exc) if isinstance(exc, ValueError) else "Database operation failed"
        print(message, file=sys.stderr)
        return 1
    finally:
        db.close()

    print(f"Initial administrator created: {user.username}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    parser.add_argument("command", choices=("bootstrap-admin",))
    arguments = parser.parse_args()
    if arguments.command == "bootstrap-admin":
        return bootstrap_admin()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
