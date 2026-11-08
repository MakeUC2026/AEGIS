"""Idempotent Auth0 tenant setup for AEGIS (M1 A-07). Safe to re-run.

Usage (from backend/): uv run python ../scripts/auth0_setup.py [--extra-origin https://app.vercel.app]

Reads AUTH0_DOMAIN, AUTH0_CLIENT_ID (web app), AUTH0_AUDIENCE and the setup M2M app
(AUTH0_MGMT_CLIENT_ID / AUTH0_MGMT_CLIENT_SECRET) from the environment. Never prints secrets.
Steps: web app URLs and grant types; roles; post-login Action; E2E test user; login theme.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import secrets
import time

import httpx

ROOT = pathlib.Path(__file__).resolve().parents[1]
ACTION_NAME = "aegis-claims"
ACTION_CODE = (pathlib.Path(__file__).parent / "auth0" / "post_login_action.js").read_text()
ROLES = {
    "student": "Default player role (no role also means student)",
    "teacher": "Classroom: sessions, insights, quizzes, secret rotation",
    "firewall_admin": "Firewall console: review queue, rules, levels, drafts, diverts",
}
E2E_EMAIL = "e2e-student@aegis.test"
LOCAL_ORIGIN = "http://localhost:3000"
THEME_COLORS = {
    "bg": "#0a0e0c",
    "panel": "#0f1512",
    "fg": "#d8f5e6",
    "muted": "#7fa08f",
    "accent": "#39ff9c",
    "accent_fg": "#04140c",
    "line": "#1f3a2e",
    "danger": "#ff6b81",
}
POLL_INTERVAL_S = 1.5
POLL_ATTEMPTS = 40
RATE_LIMIT_RETRIES = 6  # free tenants hit the Management API global limit quickly


class Mgmt:
    def __init__(self) -> None:
        self.dom = os.environ["AUTH0_DOMAIN"]
        token = httpx.post(
            f"https://{self.dom}/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": os.environ["AUTH0_MGMT_CLIENT_ID"],
                "client_secret": os.environ["AUTH0_MGMT_CLIENT_SECRET"],
                "audience": f"https://{self.dom}/api/v2/",
            },
            timeout=20,
        )
        token.raise_for_status()
        self.http = httpx.Client(
            base_url=f"https://{self.dom}/api/v2/",
            headers={"authorization": f"Bearer {token.json()['access_token']}"},
            timeout=30,
        )

    def call(self, method: str, path: str, **kw: object) -> httpx.Response:
        resp = self.http.request(method, path, **kw)  # type: ignore[arg-type]
        for attempt in range(RATE_LIMIT_RETRIES):
            if resp.status_code != httpx.codes.TOO_MANY_REQUESTS:
                break
            wait = float(resp.headers.get("retry-after", 2**attempt))
            print(f"  rate limited on {method} {path}; retrying in {wait:.0f}s")
            time.sleep(wait)
            resp = self.http.request(method, path, **kw)  # type: ignore[arg-type]
        if resp.status_code >= 400:
            raise RuntimeError(f"{method} {path} -> {resp.status_code}: {resp.text[:300]}")
        return resp


def setup_web_app(m: Mgmt, origins: list[str]) -> None:
    client_id = os.environ["AUTH0_CLIENT_ID"]
    current = m.call(
        "GET",
        f"clients/{client_id}",
        params={"fields": "callbacks,allowed_logout_urls,web_origins"},
    ).json()

    def merged(key: str, values: list[str]) -> list[str]:
        return sorted(set(current.get(key) or []) | set(values))

    m.call(
        "PATCH",
        f"clients/{client_id}",
        json={
            "callbacks": merged("callbacks", [f"{o}/auth/callback" for o in origins]),
            "allowed_logout_urls": merged("allowed_logout_urls", origins),
            "web_origins": merged("web_origins", origins),
            "grant_types": ["authorization_code", "refresh_token"],
        },
    )
    print(f"web app: URLs set for {origins}; grant types = authorization_code, refresh_token")


def setup_api_user_access(m: Mgmt) -> None:
    """Newer tenants create APIs with user access `require_client_grant`; the web app then fails
    with "not authorized to access resource server". Allow user logins, keep M2M strict."""
    audience = os.environ["AUTH0_AUDIENCE"]
    api = next(
        x for x in m.call("GET", "resource-servers").json() if x.get("identifier") == audience
    )
    m.call(
        "PATCH",
        f"resource-servers/{api['id']}",
        json={
            "subject_type_authorization": {
                "user": {"policy": "allow_all"},
                "client": {"policy": "require_client_grant"},
            }
        },
    )
    print(f"api {audience}: user logins allowed, machine clients still need a grant")


def setup_roles(m: Mgmt) -> dict[str, str]:
    existing = {r["name"]: r["id"] for r in m.call("GET", "roles").json()}
    for name, description in ROLES.items():
        if name not in existing:
            existing[name] = m.call(
                "POST", "roles", json={"name": name, "description": description}
            ).json()["id"]
            print(f"role created: {name}")
        else:
            print(f"role exists: {name}")
    return existing


def setup_action(m: Mgmt) -> None:
    actions = (
        m.call("GET", "actions/actions", params={"actionName": ACTION_NAME})
        .json()
        .get("actions", [])
    )
    body = {
        "code": ACTION_CODE,
        "runtime": "node22",
        "supported_triggers": [{"id": "post-login", "version": "v3"}],
    }
    if actions:
        action_id = actions[0]["id"]
        m.call("PATCH", f"actions/actions/{action_id}", json=body)
    else:
        action_id = m.call("POST", "actions/actions", json={"name": ACTION_NAME, **body}).json()[
            "id"
        ]
    for _ in range(POLL_ATTEMPTS):
        status = m.call("GET", f"actions/actions/{action_id}").json().get("status")
        if status == "built":
            break
        if status == "failed":
            raise RuntimeError("action build failed")
        time.sleep(POLL_INTERVAL_S)
    m.call("POST", f"actions/actions/{action_id}/deploy")
    bindings = m.call("GET", "actions/triggers/post-login/bindings").json().get("bindings", [])
    refs = [
        {
            "ref": {"type": "action_id", "value": b["action"]["id"]},
            "display_name": b["display_name"],
        }
        for b in bindings
    ]
    if not any(r["ref"]["value"] == action_id for r in refs):
        refs.append({"ref": {"type": "action_id", "value": action_id}, "display_name": ACTION_NAME})
    m.call("PATCH", "actions/triggers/post-login/bindings", json={"bindings": refs})
    print(f"action {ACTION_NAME}: built, deployed, bound to post-login")


def _env_set(key: str, value: str) -> None:
    env = ROOT / ".env"
    lines = [ln for ln in env.read_text().splitlines() if not ln.startswith(f"{key}=")]
    env.write_text("\n".join([*lines, f"{key}={value}"]) + "\n")
    env.chmod(0o600)


def setup_e2e_user(m: Mgmt, roles: dict[str, str]) -> None:
    found = m.call("GET", "users-by-email", params={"email": E2E_EMAIL}).json()
    if found:
        user_id = found[0]["user_id"]
        print(f"e2e user exists: {E2E_EMAIL}")
    else:
        password = secrets.token_urlsafe(18) + "Aa1!"
        user_id = m.call(
            "POST",
            "users",
            json={
                "connection": "Username-Password-Authentication",
                "email": E2E_EMAIL,
                "password": password,
                "email_verified": True,
                "name": "E2E Student",
            },
        ).json()["user_id"]
        _env_set("AEGIS_E2E_EMAIL", E2E_EMAIL)
        _env_set("AEGIS_E2E_PASSWORD", password)
        print(f"e2e user created: {E2E_EMAIL} (password stored in .env only)")
    m.call("POST", f"users/{user_id}/roles", json={"roles": [roles["student"]]})


def setup_theme(m: Mgmt) -> None:
    c = THEME_COLORS
    m.call(
        "PATCH", "branding", json={"colors": {"primary": c["accent"], "page_background": c["bg"]}}
    )
    theme = {
        "displayName": "AEGIS terminal",
        "borders": {
            "button_border_radius": 2,
            "button_border_weight": 1,
            "buttons_style": "sharp",
            "input_border_radius": 2,
            "input_border_weight": 1,
            "inputs_style": "sharp",
            "show_widget_shadow": False,
            "widget_border_weight": 1,
            "widget_corner_radius": 2,
        },
        "colors": {
            "base_focus_color": c["accent"],
            "base_hover_color": c["accent"],
            "body_text": c["fg"],
            "error": c["danger"],
            "header": c["fg"],
            "icons": c["muted"],
            "input_background": c["bg"],
            "input_border": c["line"],
            "input_filled_text": c["fg"],
            "input_labels_placeholders": c["muted"],
            "links_focused_components": c["accent"],
            "primary_button": c["accent"],
            "primary_button_label": c["accent_fg"],
            "secondary_button_border": c["line"],
            "secondary_button_label": c["fg"],
            "success": c["accent"],
            "widget_background": c["panel"],
            "widget_border": c["line"],
        },
        "fonts": {
            "body_text": {"bold": False, "size": 87.5},
            "buttons_text": {"bold": True, "size": 100},
            "font_url": "",
            "input_labels": {"bold": False, "size": 100},
            "links": {"bold": True, "size": 87.5},
            "links_style": "normal",
            "reference_text_size": 16,
            "subtitle": {"bold": False, "size": 87.5},
            "title": {"bold": True, "size": 150},
        },
        "page_background": {
            "background_color": c["bg"],
            "background_image_url": "",
            "page_layout": "center",
        },
        "widget": {
            "header_text_alignment": "left",
            "logo_height": 40,
            "logo_position": "none",
            "logo_url": "",
            "social_buttons_layout": "bottom",
        },
    }
    current = m.http.get("branding/themes/default")
    if current.status_code == 200:
        m.call("PATCH", f"branding/themes/{current.json()['themeId']}", json=theme)
    else:
        m.call("POST", "branding/themes", json=theme)
    print("login page theme: terminal colours applied")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--extra-origin", action="append", default=[], help="e.g. the Vercel URL")
    args = parser.parse_args()
    m = Mgmt()
    setup_web_app(m, [LOCAL_ORIGIN, *args.extra_origin])
    setup_api_user_access(m)
    roles = setup_roles(m)
    setup_action(m)
    setup_e2e_user(m, roles)
    setup_theme(m)


if __name__ == "__main__":
    main()
