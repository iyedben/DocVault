"""Tests for environment-based and safely encoded database configuration."""

from app.core.config import AuthSettings, DatabaseSettings
from app.db.session import build_database_url
from sqlalchemy.engine import make_url


def test_database_settings_come_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_HOST", "db.internal")
    monkeypatch.setenv("DATABASE_PORT", "5544")
    monkeypatch.setenv("DATABASE_NAME", "vault_test")
    monkeypatch.setenv("DATABASE_USER", "docvault_app")
    monkeypatch.setenv("DATABASE_PASSWORD", "test-only")

    settings = DatabaseSettings.from_environment()

    assert settings.host == "db.internal"
    assert settings.port == 5544
    assert settings.name == "vault_test"
    assert settings.user == "docvault_app"
    assert settings.password == "test-only"


def test_cookie_secure_setting_is_configurable(monkeypatch) -> None:
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")
    assert AuthSettings.from_environment().cookie_secure
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "false")
    assert not AuthSettings.from_environment().cookie_secure


def test_connection_url_safely_encodes_special_password_characters() -> None:
    settings = DatabaseSettings(
        host="postgres",
        port=5432,
        name="docvault",
        user="docvault_app",
        password="p@ss:/?#% word",
    )

    url = build_database_url(settings)
    rendered = url.render_as_string(hide_password=False)

    assert url.drivername == "postgresql+psycopg"
    assert url.password == "p@ss:/?#% word"
    assert "p%40ss%3A%2F%3F%23%25 word" in rendered
    assert "p@ss:/?#% word" not in rendered
    assert make_url(rendered).password == settings.password
