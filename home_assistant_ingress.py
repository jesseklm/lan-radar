import json
import os
import urllib.request

from nicegui import app
from starlette.responses import PlainTextResponse

HOME_ASSISTANT_INGRESS = os.getenv("HOME_ASSISTANT_INGRESS", "").lower() in {"1", "true", "yes"}
HOME_ASSISTANT_INGRESS_PROXY = "172.30.32.2"


class HomeAssistantIngressMiddleware:
    def __init__(self, application):
        self.application = application

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            await self.application(scope, receive, send)
            return

        headers = list(scope.get("headers", []))
        ingress_path = next((value for name, value in headers if name == b"x-ingress-path"), None)
        client = scope.get("client")
        if not ingress_path or not client or client[0] != HOME_ASSISTANT_INGRESS_PROXY:
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:
                await PlainTextResponse("Forbidden", status_code=403)(scope, receive, send)
            return

        headers = [(name, value) for name, value in headers if name != b"x-forwarded-prefix"]
        headers.append((b"x-forwarded-prefix", ingress_path.rstrip(b"/")))
        scope["headers"] = headers
        await self.application(scope, receive, send)


if HOME_ASSISTANT_INGRESS:
    app.add_middleware(HomeAssistantIngressMiddleware)


def get_ingress_port() -> int:
    token = os.environ["SUPERVISOR_TOKEN"]
    request = urllib.request.Request("http://supervisor/addons/self/info",
                                     headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request) as response:
        result = json.load(response)
    return result["data"]["ingress_port"]
