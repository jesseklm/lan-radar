import logging
import os

from authlib.integrations.base_client import OAuthError
from authlib.integrations.starlette_client import OAuth
from nicegui import app, ui
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

configuration = {
    "KEYCLOAK_BASE_URL": os.environ.get("KEYCLOAK_BASE_URL", "").strip().rstrip("/"),
    "KEYCLOAK_REALM": os.environ.get("KEYCLOAK_REALM", "").strip(),
    "KEYCLOAK_CLIENT_ID": os.environ.get("KEYCLOAK_CLIENT_ID", "").strip(),
    "KEYCLOAK_CLIENT_SECRET": os.environ.get("KEYCLOAK_CLIENT_SECRET", ""),
}
STORAGE_SECRET = os.environ.get("STORAGE_SECRET", "")
KEYCLOAK_ENABLED = any(configuration.values())
if KEYCLOAK_ENABLED:
    missing_variables = [name for name, value in configuration.items() if not value]
    if not STORAGE_SECRET:
        missing_variables.append("STORAGE_SECRET")
    if missing_variables:
        raise RuntimeError("Incomplete Keycloak configuration; missing environment variables: "
                           + ", ".join(missing_variables))


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if (
                request.url.path.startswith("/_nicegui")
                or request.url.path in {"/login", "/login/keycloak", "/auth/keycloak"}
                or app.storage.user.get("is_authenticated", False)
        ):
            return await call_next(request)
        app.storage.user["referrer_path"] = request.url.path
        return RedirectResponse("/login")


if KEYCLOAK_ENABLED:
    oauth = OAuth()
    oauth.register(
        name="keycloak",
        client_id=configuration["KEYCLOAK_CLIENT_ID"],
        client_secret=configuration["KEYCLOAK_CLIENT_SECRET"],
        server_metadata_url=f"{configuration['KEYCLOAK_BASE_URL']}/realms/{configuration['KEYCLOAK_REALM']}/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
    )
    app.add_middleware(AuthMiddleware)


    @app.get("/login/keycloak")
    async def keycloak_login(request: Request) -> RedirectResponse:
        if app.storage.user.get("is_authenticated"):
            return RedirectResponse("/")
        redirect_uri = request.url_for("keycloak_callback")
        return await oauth.keycloak.authorize_redirect(request, redirect_uri)


    @app.get("/auth/keycloak")
    async def keycloak_callback(request: Request) -> RedirectResponse:
        try:
            token = await oauth.keycloak.authorize_access_token(request)
        except OAuthError as exc:
            logging.warning("Keycloak authentication failed: %s", exc)
            return RedirectResponse("/login?error=oauth")

        userinfo = token.get("userinfo") or {}
        username = userinfo.get("preferred_username") or userinfo.get("email") or userinfo.get("sub")
        if not username:
            logging.warning("Keycloak authentication failed: token contains no user identity")
            return RedirectResponse("/login?error=identity")
        email = userinfo.get("email") if userinfo.get("email_verified", True) else None
        referrer_path = app.storage.user.get("referrer_path", "/")
        if not isinstance(referrer_path, str) or not referrer_path.startswith("/") or referrer_path.startswith(
                "//"):
            referrer_path = "/"
        app.storage.user.clear()
        app.storage.user.update({
            "is_authenticated": True,
            "auth": {"provider": "keycloak", "name": username, "email": email},
        })
        return RedirectResponse(referrer_path)


    @app.get("/logout")
    async def logout(request: Request) -> RedirectResponse:
        app.storage.user.clear()
        request.session.clear()
        return RedirectResponse("/login")


    @ui.page("/login", title="Login")
    def login_page(request: Request):
        if app.storage.user.get("is_authenticated"):
            return RedirectResponse("/")
        with ui.card().classes("max-w-md mx-auto mt-24 p-6"):
            ui.label("Please sign in").classes("text-xl mb-4")
            if request.query_params.get("error"):
                ui.label("Authentication failed. Please try again.").classes("text-negative mb-2")
            ui.button(
                "Sign in with Keycloak",
                on_click=lambda: ui.navigate.to("/login/keycloak"),
                icon="login",
            ).classes("w-full")
        return None


def get_username() -> str:
    auth = app.storage.user.get("auth", {})
    return str(auth.get("name", "")) if isinstance(auth, dict) else ""
