# http приманка: фейковая админка, логирует все запросы
import asyncio
import re
from urllib.parse import unquote_plus, parse_qs

from aiohttp import web

from honeypot.events import Event, HTTP_REQUEST
from honeypot.logger import EventLogger
from honeypot.storage.db import Storage

# признаки атак: название -> регулярка
PATTERNS = {
    "sqli": r"'\s*(or|and)\s|union\s+select|sleep\(|'\s*(--|#)",
    "xss": r"<script|onerror\s*=|javascript:",
    "traversal": r"\.\./|\.\.\\|/etc/passwd|boot\.ini",
    "rce": r";\s*(cat|wget|curl|nc|bash|sh)\b|\$\(|`|\|\s*(sh|bash)\b",
    "scanner": r"nikto|sqlmap|nmap|masscan|zgrab|dirbuster|gobuster",
}

# страницы, где показываем форму входа
LOGIN_PATHS = {"/", "/admin", "/login", "/wp-login.php", "/phpmyadmin"}

LOGIN_PAGE = """<html><head><title>Admin Login</title></head>
<body><h2>Admin panel</h2>
<form method="post" action="/login">
<input name="username" placeholder="username"><br>
<input name="password" type="password" placeholder="password"><br>
<button>Login</button></form></body></html>"""

FAKE_HEADERS = {"Server": "Apache/2.4.41 (Ubuntu)"}


def detect_attacks(text):
    # возвращает список найденных типов атак
    text = unquote_plus(text).lower()
    return [name for name, rx in PATTERNS.items() if re.search(rx, text)]


def make_app(logger):
    async def handler(request):
        body = (await request.text())[:2000]  # режем, чтобы не копить мусор
        ua = request.headers.get("User-Agent", "")
        peer = request.transport.get_extra_info("peername") or ("?", 0)
        ip, port = peer[0], peer[1]

        payload = {
            "method": request.method,
            "path": request.path,
            "query": request.query_string,
            "user_agent": ua,
            "body": body,
            "attacks": detect_attacks(f"{request.path_qs} {body} {ua}"),
        }

        # логин и пароль из формы (у wordpress поля log и pwd)
        if request.method == "POST" and request.path in LOGIN_PATHS:
            form = parse_qs(body)
            payload["user"] = form.get("username", form.get("log", [""]))[0]
            payload["password"] = form.get("password", form.get("pwd", [""]))[0]

        logger.log(Event("http", HTTP_REQUEST, ip, port, payload=payload))

        if request.path in LOGIN_PATHS:
            if request.method == "POST":
                return web.Response(text="Wrong username or password", status=401,
                                    headers=FAKE_HEADERS)
            return web.Response(text=LOGIN_PAGE, content_type="text/html",
                                headers=FAKE_HEADERS)
        return web.Response(text="Not Found", status=404, headers=FAKE_HEADERS)

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)  # ловим любые пути
    return app


async def start_server(host="0.0.0.0", port=8080, db_path="logs/events.db",
                       log_path="logs/events.jsonl"):
    logger = EventLogger(log_path, storage=Storage(db_path))
    runner = web.AppRunner(make_app(logger), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, host, port).start()
    return runner


async def main():
    await start_server()
    print("http honeypot слушает порт 8080")
    await asyncio.Event().wait()  # висим пока не остановим


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("стоп")