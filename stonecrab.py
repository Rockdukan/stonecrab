import argparse
import ast
import contextlib
import ftplib
import json
import email.message
import email.utils
import hmac
import mimetypes
import operator
import os
import re
import secrets
import platform
import smtplib
import socket
import ssl
import string
import subprocess
import sys
import threading
import time
import types
import uuid
import urllib.parse
import urllib.request
from datetime import datetime
from http.cookies import SimpleCookie
from inspect import isclass, isfunction
from pathlib import Path

try:
    import settings
except ImportError:
    _cwd = os.getcwd()
    settings = types.SimpleNamespace(
        PROJECT_DIR=_cwd,
        MEDIA_URL="/media/",
        MEDIA_DIR=os.path.join(_cwd, "media"),
        STATIC_URL="/static/",
        STATIC_DIR=os.path.join(_cwd, "static"),
        TEMPLATE_DIRS=os.path.join(_cwd, "templates"),
        MIDDLEWARE=[])

# TODO: Написать тесты
# TODO: Посмотреть видео про параллельный запуск скриптов, попробовать внедрить
# TODO: Сделать бенчмарк с Flask, Bottle, Web2py, Sanic, Tornado, Falcon, Pyramid, Django
# TODO: Реализовать загрузку файла через форму на странице
# TODO: Проверить работу с nginx
# TODO: Прочитать про Spider (асинхронные запросы)
# TODO: Сделать в routes именованный параметр как as_view в Django
# TODO: COOKIE_KEY / secret_key для подписи cookie

# **********************************************************************
# ************************** Session storage ***************************
# **********************************************************************
SESSION_STORE = {}


# **********************************************************************
# ***************************** HTTP helpers ***************************
# **********************************************************************
def contains_whitespace(s):
    """Возвращает True, если в строке есть хотя бы один пробельный символ."""
    return any(c in s for c in string.whitespace)


def flatten_parse_result(qs_dict):
    """
    Сжимает результат urllib.parse.parse_qs до плоского словаря (последнее значение ключа).

    Args:
        qs_dict: Словарь имя -> список строк.

    Returns:
        Словарь имя -> str.
    """
    out = {}
    for k, v in qs_dict.items():
        if v:
            out[k] = v[-1]
    return out


def build_set_cookie_value(
    name,
    value,
    max_age=None,
    path="/",
    httponly=True,
    secure=False,
    samesite="Lax",):
    """
    Формирует значение одного заголовка Set-Cookie (без префикса имени заголовка).

    Args:
        name: Имя cookie.
        value: Значение cookie.
        max_age: Необязательный Max-Age в секундах.
        path: Атрибут Path.
        httponly: Добавлять ли флаг HttpOnly.
        secure: Флаг Secure (обычно True за HTTPS).
        samesite: Значение SameSite (Lax, Strict, None).

    Returns:
        Строка тела cookie для заголовка Set-Cookie.
    """
    parts = [f"{name}={value}", f"Path={path}"]
    if max_age is not None:
        parts.append(f"Max-Age={int(max_age)}")
    if httponly:
        parts.append("HttpOnly")
    if secure:
        parts.append("Secure")
    if samesite and str(samesite).lower() != "none":
        parts.append(f"SameSite={samesite}")
    elif str(samesite).lower() == "none":
        parts.append("SameSite=None")
    return "; ".join(parts)


def parse_multipart_body(body, boundary, default_charset="utf-8"):
    """
    Разбирает тело запроса multipart/form-data.

    Args:
        body: Сырые байты тела.
        boundary: Значение параметра boundary из Content-Type (без префикса --).
        default_charset: Кодировка для текстовых полей.

    Returns:
        Кортеж (fields, files): поля формы и вложения с ключами filename,
        content_type, data.
    """
    fields = {}
    files = {}
    if not boundary:
        return fields, files
    delim = b"--" + boundary.encode("ascii")
    parts = body.split(delim)
    for part in parts:
        part = part.strip()
        if not part or part == b"--":
            continue
        if part.startswith(b"\r\n"):
            part = part[2:]
        elif part.startswith(b"\n"):
            part = part[1:]
        header_end = part.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = part.find(b"\n\n")
            if header_end == -1:
                continue
            headers_blob = part[:header_end].decode("latin-1", errors="replace")
            raw_body = part[header_end + 2 :]
        else:
            headers_blob = part[:header_end].decode("latin-1", errors="replace")
            raw_body = part[header_end + 4 :]
        if raw_body.endswith(b"\r\n"):
            raw_body = raw_body[:-2]
        elif raw_body.endswith(b"\n"):
            raw_body = raw_body[:-1]
        disp = None
        ctype = "text/plain"
        for line in headers_blob.split("\n"):
            line = line.strip()
            if line.lower().startswith("content-disposition:"):
                disp = line.split(":", 1)[1].strip()
            elif line.lower().startswith("content-type:"):
                ctype = line.split(":", 1)[1].strip().split(";")[0].strip()
        if not disp or "form-data" not in disp.lower():
            continue
        name = None
        filename = None
        for token in disp.split(";"):
            token = token.strip()
            if token.startswith("name="):
                name = token[5:].strip().strip('"')
            elif token.startswith("filename="):
                filename = token[9:].strip().strip('"')
        if not name:
            continue
        if filename is not None:
            files[name] = {
                "filename": filename,
                "content_type": ctype,
                "data": raw_body}
        else:
            charset = default_charset
            if "charset=" in ctype.lower():
                pass
            try:
                fields[name] = raw_body.decode(charset, errors="replace")
            except LookupError:
                fields[name] = raw_body.decode("utf-8", errors="replace")
    return fields, files


CSRF_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

_CACHE_LOCK = threading.Lock()
_RESPONSE_CACHE = {}
_IDEMPOTENCY_CACHE = {}
_RATE_BUCKET = {}


def log_event(event, **fields):
    """Пишет одну JSON-строку в stderr (структурный лог)."""
    row = {"event": event, "ts": time.time(), **fields}
    sys.stderr.write(json.dumps(row, ensure_ascii=False) + "\n")


def parse_json_body(request):
    """Разбор тела как JSON; при ошибке возвращает None."""
    if not request.body:
        return None
    try:
        raw = request.body.decode(request.charset, errors="replace")
    except LookupError:
        raw = request.body.decode("utf-8", errors="replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def validate_payload(data, schema):
    """
    Простая проверка словаря по схеме.

    schema: имя -> тип (type) или кортеж типов, либо callable(value) -> bool.
    Отсутствующий ключ с типом int/str/... считается ошибкой; для optional используйте callable.
    """
    errors = []
    if not isinstance(data, dict):
        return ["payload must be dict"]
    for key, spec in schema.items():
        val = data.get(key)
        if val is None or val == "":
            errors.append(f"missing:{key}")
            continue
        if isinstance(spec, (type, tuple)):
            if not isinstance(val, spec):
                errors.append(f"type:{key}")
        elif callable(spec):
            try:
                if not spec(val):
                    errors.append(f"invalid:{key}")
            except Exception:
                errors.append(f"check:{key}")
        else:
            errors.append(f"bad_schema:{key}")
    return errors


def build_openapi_spec(routes):
    """Минимальная OpenAPI 3.0: paths и HTTP-методы из @route / View."""
    paths = {}
    for path, handler in sorted(routes.items(), key=lambda x: x[0]):
        p = path.rstrip("/") or "/"
        entry = {}
        if isclass(handler):
            allowed = getattr(handler, STONE_CRAB_METHODS, None) or frozenset(("GET", "HEAD", "OPTIONS"))
            for m in sorted(allowed):
                entry[m.lower()] = {
                    "summary": handler.__name__,
                    "responses": {"200": {"description": "OK"}}}
        else:
            allowed = getattr(handler, STONE_CRAB_METHODS, frozenset(("GET", "HEAD", "OPTIONS")))
            for m in sorted(allowed):
                entry[m.lower()] = {
                    "summary": getattr(handler, "__name__", "handler"),
                    "responses": {"200": {"description": "OK"}}}
        paths[p] = entry
    return {"openapi": "3.0.0", "info": {"title": "StoneCrab", "version": "1.0"}, "paths": paths}

# **********************************************************************
# ***************************** Status codes ***************************
# **********************************************************************
STATUS_CODES = {
    # 2xx
    200: "OK",
    201: "Created",
    204: "No Content",
    # 3xx
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    # 4xx
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    413: "Payload Too Large",
    415: "Unsupported Media Type",
    429: "Too Many Requests",
    # 5xx
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Time-out"}


# Имена атрибутов, которые выставляет декоратор route()
STONE_CRAB_ROUTE = "_stonecrab_route"
STONE_CRAB_METHODS = "_stonecrab_methods"


def route(path, methods=None):
    """
    Декоратор для функции или класса View: привязка к URL и списку HTTP-методов.

    Маршруты из views с этим декоратором подхватываются при загрузке приложения
    наряду с явным словарём urls в routes.py.

    Args:
        path: Путь относительно префикса приложения (как в urls).
        methods: Кортеж методов (по умолчанию GET, HEAD, OPTIONS).

    Returns:
        Декоратор, возвращающий исходный объект с метаданными маршрута.
    """
    allowed = tuple(m.upper() for m in (methods or ("GET", "HEAD", "OPTIONS")))

    def decorator(target):
        setattr(target, STONE_CRAB_ROUTE, path)
        setattr(target, STONE_CRAB_METHODS, frozenset(allowed))
        return target

    return decorator


def wrap_view_method_guard(view_callable, allowed_methods):
    """
    Оборачивает функцию-представление: неразрешённый метод даёт 405.

    Args:
        view_callable: Исходная view-функция.
        allowed_methods: Множество или последовательность имён методов в верхнем регистре.

    Returns:
        Обертка с той же сигнатурой (request, response, **kwargs).
    """
    allowed = frozenset(m.upper() for m in allowed_methods)

    def guarded(request, response, **kwargs):
        if request.method not in allowed:
            response.status_code = 405
            response.headers.setdefault("Content-Type", f"text/plain; charset={response.charset}")
            response.text = STATUS_CODES[405]
            return response

        return view_callable(request, response, **kwargs)

    return guarded


def require_schema(schema):
    """
    Декоратор view: validate_payload(request.get_form(), schema).
    При ошибках — 400 и текст с перечислением полей.
    """
    def decorator(fn):
        def guarded(request, response, **kwargs):
            errs = validate_payload(request.get_form(), schema)
            if errs:
                response.status_code = 400
                response.headers.setdefault("Content-Type", f"text/plain; charset={response.charset}")
                response.text = "; ".join(errs)
                return response
            return fn(request, response, **kwargs)

        return guarded

    return decorator


# **********************************************************************
# *********************** Project settings package *********************
# **********************************************************************
SETTINGS_INIT_PY = """# -*- coding: utf-8 -*-
import os

_env = os.environ.get("STONECRAB_ENV", "development").lower()
if _env == "production":
    from .production import *  # noqa: F401,F403
else:
    from .development import *  # noqa: F401,F403
"""

SETTINGS_BASE_PY = '''# -*- coding: utf-8 -*-
"""Общие настройки (пути, middleware, лимиты). Окружение — development / production."""
import os

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET_KEY = os.environ.get("STONECRAB_SECRET_KEY", "change-me-in-production")

SESSION_COOKIE_NAME = "stonecrab_sid"
CSRF_HEADER_NAME = "X-CSRF-Token"
AUTH_SESSION_KEY = "auth_user_id"
SESSION_COOKIE_SECURE = None
SESSION_COOKIE_SAMESITE = "Lax"

MEDIA_URL = "/media/"
MEDIA_DIR = os.path.join(PROJECT_DIR, "media")
STATIC_URL = "/static/"
STATIC_DIR = os.path.join(PROJECT_DIR, "static")
TEMPLATE_DIRS = os.path.join(PROJECT_DIR, "templates")

MAX_REQUEST_BODY_BYTES = 10_000_000
MAX_HTTP_HEADERS = 80
CORS_ORIGINS = []
API_PATH_PREFIXES = ("/api",)
HSTS_MAX_AGE = 31536000
HSTS_INCLUDE_SUBDOMAINS = False
SENSITIVE_CACHE_PATH_PREFIXES = ("/api", "/admin")
HEALTH_PATH = "/health"
OPENAPI_PATH = "/openapi.json"
API_VERSION_PREFIX = ""
RESPONSE_CACHE_TTL = 0
IDEMPOTENCY_TTL = 3600
BEFORE_REQUEST_HOOKS = []
AFTER_REQUEST_HOOKS = []

# Порядок: внешний слой первым (ближе к клиенту).
MIDDLEWARE = [
    "TrustedHostMiddleware",
    "RequestLimitsMiddleware",
    "RateLimitMiddleware",
    "CorsMiddleware",
    "ApiOriginMiddleware",
    "MetricsMiddleware",
    "SecurityMiddleware",
    "HstsMiddleware",
    "SensitiveCacheMiddleware",
    "AuthenticationMiddleware",
    "ApiVersionPrefixMiddleware",
    "CsrfMiddleware",
    "SessionMiddleware",
    "IdempotencyMiddleware",
    "ResponseCacheMiddleware",
    "StaticfilesMiddleware",
    "GzipMiddleware",
    "LogMiddleware",
    "RequestHooksMiddleware",
    "MessageMiddleware",
    "CleanHTMLMiddleware",
]
'''

SETTINGS_DEVELOPMENT_PY = '''# -*- coding: utf-8 -*-
from .base import *  # noqa: F401,F403

DEBUG = True
ALLOWED_HOSTS = ["*"]
RATE_LIMIT_PER_MINUTE = 0
API_ENFORCE_ORIGIN = False
'''

SETTINGS_PRODUCTION_PY = '''# -*- coding: utf-8 -*-
import os
from .base import *  # noqa: F401,F403

DEBUG = False

_raw_hosts = os.environ.get("ALLOWED_HOSTS", "").strip()
ALLOWED_HOSTS = [h.strip() for h in _raw_hosts.split(",") if h.strip()]
if not ALLOWED_HOSTS:
    raise RuntimeError("ALLOWED_HOSTS не задан. Пример: export ALLOWED_HOSTS=example.com,www.example.com")

RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "120"))
SESSION_COOKIE_SECURE = True
API_ENFORCE_ORIGIN = os.environ.get("API_ENFORCE_ORIGIN", "1") not in ("0", "false", "False")

_cors = os.environ.get("CORS_ORIGINS", "").strip()
CORS_ORIGINS = [x.strip() for x in _cors.split(",") if x.strip()] if _cors else []
'''


routes_template = (
    "# -*- coding: utf-8 -*-\n"
    "from . import views\n\n"
    "urls = {}\n"
    "# Явные пары путь -> обработчик; маршруты с @route в views подключаются автоматически.\n")


views_template = (
    "from stonecrab import render, route\n\n\n"
    '@route("/")\n'
    "def index(request, response):\n"
    "    context = {\n"
    '        "title": "Stonecrab",\n'
    '        "welcom": "Welcom",\n'
    "    }\n"
    '    return render("index.html", context, version="v.0.1")\n')


# **********************************************************************
# ******************************* Messages *****************************
# **********************************************************************
class Messages:
    """
    Вывод служебных сообщений в терминал с ANSI-цветами.

    Notes:
        Методы вызываются как Messages.method(...) без экземпляра.
    """
    def out_allowed(text):
        """Печатает сообщение категории «разрешено»."""
        print(f"\033[36m✅ [ALLOWED]: \033[33m{text}\033[0m")

    def out_error(text):
        """Печатает сообщение об ошибке."""
        print(f"\033[31m❌ [ERROR]: \033[31m{text}\033[0m")

    def out_forbidden(text):
        """Печатает сообщение о запрете доступа."""
        print(f"\033[35m🔒 [FORBIDDEN]: \033[33m{text}\033[0m")

    def out_info(text):
        """Печатает информационное сообщение."""
        print(f"\033[34mℹ️ [INFO]: \033[36m{text}\033[0m")

    def out_msg(text):
        """Печатает нейтральное сообщение."""
        print(f"\033[36m📎 {text}\033[0m")

    def out_warning(text):
        """Печатает предупреждение."""
        print(f"\033[33m⚠️ [WARNING]: \033[33m{text}\033[0m")

    class Errors:
        """Зарезервировано для группировки текстов ошибок."""

        pass

    class Info:
        """Зарезервировано для группировки информационных текстов."""

        pass

    class Warning:
        """Зарезервировано для группировки предупреждений."""

        pass

    def error_bad_request(request, response, **kwargs):
        """Логирует ответ с кодом 400 Bad Request."""
        Messages.out_error(f"🚫 [{request.method}] CODE:400 '{request.path}' {STATUS_CODES[400]}")

    def error_prefix(app="", prefix=""):
        """Сообщает об ошибке чтения префикса URL приложения."""
        Messages.out_error(f"🔗 Ошибка URL-префикса >>> '{prefix}' <<< для приложения >>> '{app}' <<<")

    def error_response(request, response):
        """Логирует ответ с кодом ошибки по фактическому status_code."""
        path = request.path.rstrip("/")
        code = int(response.status_code)
        phrase = STATUS_CODES.get(code, f"HTTP {code}")
        Messages.out_error(f"📛 [{request.method}] CODE:{code} '{path}' {phrase}")

    def error_method_not_detected(request):
        """Сообщает, что для маршрута не найден обработчик HTTP-метода."""
        Messages.out_error(f"🛤️ Метод '{request.method}' для '{request.path}' не найден")

    def error_no_found_apps_folder():
        """Сообщает об отсутствии каталога apps."""
        Messages.out_error("📂 Нет каталога apps")

    def error_no_parameter():
        """Сообщает о вызове CLI без обязательного параметра."""
        Messages.out_error("⌨️ Не указан параметр команды")

    def error_route_already_exists(path):
        """Сообщает о дублировании маршрута при регистрации."""
        Messages.out_error(f"⛔ Маршрут '{path}' уже зарегистрирован")

    def error_unknown_parameter():
        """Сообщает о неизвестной подкоманде CLI."""
        Messages.out_error("❓ Неизвестный параметр CLI")

    def info_create_app(name):
        """Сообщает об успешном создании приложения."""
        Messages.out_info(f"📦 Application \033[35m{name} \033[36mcreate")

    def info_create_file(name):
        """Сообщает об успешном создании файла."""
        Messages.out_info(f"📄 File \033[35m{name} \033[36mcreate")

    def info_create_folder(name):
        """Сообщает об успешном создании каталога."""
        Messages.out_info(f"📁 Folder \033[35m{name} \033[36mcreate")

    def info_response(request, response):
        """Логирует успешный HTTP-ответ (код 2xx или редирект)."""
        path = request.path.rstrip("/")
        code = int(response.status_code)
        phrase = STATUS_CODES.get(code, f"HTTP {code}")
        Messages.out_info(f"🌐 [{request.method}] CODE:{code} '{path}' {phrase}")

    def info_upd_app(name):
        """Сообщает об обновлении приложения (например, при startproject)."""
        Messages.out_info(f"🔄 Application \033[35m{name} \033[36mupdate")

    def warning_spaces_url_prefix(app=""):
        """Предупреждает о пробелах в URL_PREFIX."""
        Messages.out_warning(
            f"🔤 Приложение >>> '{app}' <<< — в URL_PREFIX пробелы, "
            f"будет использовано имя приложения")

    def warning_slash_url_prefix(app=""):
        """Предупреждает о URL_PREFIX, равном одному слешу."""
        Messages.out_warning(
            f"➗ Приложение >>> '{app}' <<< — URL_PREFIX равен одному слешу, "
            f"будет использовано имя приложения")

    def warning_empty_url_prefix(app=""):
        """Предупреждает о пустом URL_PREFIX."""
        Messages.out_warning(
            f"📭 Приложение >>> '{app}' <<< — пустой URL_PREFIX, "
            f"будет использовано имя приложения")

    def warning_none_url_prefix(app=""):
        """Предупреждает о URL_PREFIX со значением None."""
        Messages.out_warning(
            f"∅ Приложение >>> '{app}' <<< — URL_PREFIX равен None, "
            f"будет использовано имя приложения")

    def warning_no_url_prefix(app=""):
        """Предупреждает об отсутствии атрибута URL_PREFIX в routes."""
        Messages.out_warning(
            f"📋 Приложение >>> '{app}' <<< — нет атрибута URL_PREFIX в routes, "
            f"будет использовано имя приложения")


# **********************************************************************
# ******************************* Utilities ****************************
# **********************************************************************
class Utilities:
    """
    Вспомогательные функции для маршрутизации, HTTP и файловой системы.

    Notes:
        Вложенные классы группируют статические методы по назначению.
    """
    class FileSystem:
        """Работа с файловой системой."""

        @staticmethod
        def check_for_file(path):
            return os.path.isfile(path)

        @staticmethod
        def create_file(name, content=""):
            parent = os.path.dirname(os.path.abspath(name))
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(name, "w", encoding="utf-8") as fh:
                fh.write(content)

        @staticmethod
        def create_folder(name):
            Path(name).mkdir(parents=True, exist_ok=True)

        @staticmethod
        def delete_file(path):
            os.remove(path)

    class HTTP:
        """HTTP-вспомогательные функции."""

        @staticmethod
        def generate_last_modified(file_path=None):
            if file_path and os.path.isfile(file_path):
                mtime = os.path.getmtime(file_path)
                return email.utils.formatdate(mtime, usegmt=True)
            return email.utils.formatdate(usegmt=True)

        @staticmethod
        def get_etag(file_path):
            stat = os.stat(file_path)
            return f'"{stat.st_mtime_ns}-{stat.st_size}"'

    class Network:
        """
        Удобные обёртки для оборудования и серверов на чистом stdlib.

        Есть: TCP/UDP (socket), TLS (ssl), FTP (ftplib), HTTP-клиент (urllib),
        SMTP (smtplib), грубая проверка ICMP через системный ping (subprocess).
        Нет в stdlib: SSH/SFTP, SNMP, Telnet-клиент (3.13+), переносимый raw ICMP —
        используйте PyPI (Paramiko, pysnmp и т.д.) или вызов внешних утилит.
        """

        @staticmethod
        def tcp_connect(host, port, timeout=10.0):
            return socket.create_connection((host, int(port)), timeout=timeout)

        @staticmethod
        def tcp_exchange(host, port, send=b"", recv_max=65536, timeout=10.0):
            with socket.create_connection((host, int(port)), timeout=timeout) as s:
                if send:
                    s.sendall(send)
                return s.recv(recv_max)

        @staticmethod
        def udp_send_recv(host, port, payload, recv_max=65536, timeout=5.0):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(payload, (host, int(port)))
                try:
                    data, addr = s.recvfrom(recv_max)
                    return data, addr
                except socket.timeout:
                    return None, None

        @staticmethod
        def tls_connect(host, port, timeout=10.0, context=None):
            ctx = context or ssl.create_default_context()
            raw = socket.create_connection((host, int(port)), timeout=timeout)
            try:
                return ctx.wrap_socket(raw, server_hostname=host)
            except Exception:
                raw.close()
                raise

        @staticmethod
        @contextlib.contextmanager
        def ftp_session(host, user="", passwd="", timeout=30, passive=True):
            ftp = ftplib.FTP()
            ftp.connect(host, timeout=timeout)
            ftp.login(user, passwd)
            if passive:
                ftp.set_pasv(True)
            try:
                yield ftp
            finally:
                try:
                    ftp.quit()
                except Exception:
                    ftp.close()

        @staticmethod
        def http_request(url, method="GET", data=None, headers=None, timeout=30):
            m = method.upper()
            req = urllib.request.Request(url, data=data, method=m)
            if headers:
                for hk, hv in headers.items():
                    req.add_header(hk, hv)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
                return body, resp.status, dict(resp.headers)

        @staticmethod
        def smtp_send(
            host,
            port,
            from_addr,
            to_addrs,
            message,
            user=None,
            password=None,
            use_tls=True,):
            if isinstance(to_addrs, str):
                to_addrs = [to_addrs]
            with smtplib.SMTP(host, int(port), timeout=30) as smtp:
                if use_tls:
                    smtp.starttls(context=ssl.create_default_context())
                if user is not None and password is not None:
                    smtp.login(user, password)
                smtp.sendmail(from_addr, to_addrs, message)

        @staticmethod
        def ping_host(host, timeout_sec=5):
            """
            Запуск системного ping; на Windows и Unix флаги различаются.
            Возвращает (успех: bool, объединённый вывод stdout/stderr).
            """
            system = platform.system().lower()
            if system == "windows":
                cmd = [
                    "ping", "-n", "1", "-w", str(max(1, int(timeout_sec * 1000))), host]
            else:
                cmd = ["ping", "-c", "1", host]
            try:
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=float(timeout_sec) + 3.0)
                out = (cp.stdout or "") + (cp.stderr or "")
                return cp.returncode == 0, out
            except (subprocess.TimeoutExpired, OSError) as exc:
                return False, str(exc)

    class URL:
        """Вспомогательные утилиты для работы с URL."""

        def add_slash(path):
            """
            Проверяет наличие обратной косой черты в начале
            и конец URL-адреса, если нет, то добавляет.
            """
            if not path.startswith("/"):
                path = "/" + path
            if not path.endswith("/"):
                path = path + "/"
            return path

        def get_url_prefix(app):
            """Проверяет наличие URL префикса и возвращает его."""
            if app == "index":
                prefix = ""
            else:
                try:
                    module_prefix = __import__(f"apps.{app}.routes", fromlist=["object"])
                    prefix = f"{module_prefix.URL_PREFIX}".lower().rstrip("/")

                    if prefix == "/":
                        prefix = f"/{app}"
                        Messages.warning_slash_url_prefix(app=f"{app}")
                    elif prefix == "":
                        prefix = f"/{app}"
                        Messages.warning_empty_url_prefix(app=f"{app}")
                    elif contains_whitespace(prefix):
                        prefix = f"/{app}"
                        Messages.warning_spaces_url_prefix(app=f"{app}")
                    elif prefix == "none":
                        prefix = f"/{app}"
                        Messages.warning_none_url_prefix(app=f"{app}")
                    elif prefix == app:
                        prefix = f"/{app}"
                    elif prefix == f"/{app}":
                        prefix = f"{app}"
                    else:
                        Messages.error_prefix(app=f"{app}", prefix=prefix)
                except AttributeError:
                    Messages.warning_no_url_prefix(app=f"{app}")
                    prefix = f"/{app}"
                if not prefix.startswith("/"):
                    prefix = f"/{prefix}"
            return prefix

        def slugify(string):
            """Формирование url на основе переданной строки"""
            pattern = r"[^\w+]"
            slug = str(re.sub(pattern, "-", string)).lower()
            return slug

        def parse(path, request_path):
            """Парсим url, и возвращаем значения, если они есть"""
            path = path.strip().strip("/").strip().split("/")
            request_path = request_path.strip("/").split("/")
            variables = {}
            result = {}
            if path == request_path:
                result["status"], result["variables"] = True, {}
                return result
            else:
                if len(path) == len(request_path):
                    for num in range(0, len(request_path)):
                        if path[num].strip() == request_path[num].strip():
                            continue
                        elif Utilities.check_var(path[num]):
                            key = path[num].strip("{").strip("}").strip()
                            variables[key] = request_path[num]
                            continue
                        else:
                            result["status"], result["variables"] = False, {}
                            return result
                    result["status"], result["variables"] = True, variables
                    return result
                else:
                    result["status"], result["variables"] = False, {}

                    return result

    def transliterate_ru(string):
        """Транслитерация символов русского языка в латиницу"""
        dictionary = {
            "а": "a",
            "б": "b",
            "в": "v",
            "г": "g",
            "д": "d",
            "е": "e",
            "ё": "e",
            "ж": "zh",
            "з": "z",
            "и": "i",
            "й": "i",
            "к": "k",
            "л": "l",
            "м": "m",
            "н": "n",
            "о": "o",
            "п": "p",
            "р": "r",
            "с": "s",
            "т": "t",
            "у": "u",
            "ф": "f",
            "х": "h",
            "ц": "c",
            "ч": "cz",
            "ш": "sh",
            "щ": "scz",
            "ъ": "",
            "ы": "y",
            "ь": "",
            "э": "e",
            "ю": "u",
            "я": "ja",
            "А": "A",
            "Б": "B",
            "В": "V",
            "Г": "G",
            "Д": "D",
            "Е": "E",
            "Ё": "E",
            "Ж": "ZH",
            "З": "Z",
            "И": "I",
            "Й": "I",
            "К": "K",
            "Л": "L",
            "М": "M",
            "Н": "N",
            "О": "O",
            "П": "P",
            "Р": "R",
            "С": "S",
            "Т": "T",
            "У": "U",
            "Ф": "F",
            "Х": "H",
            "Ц": "C",
            "Ч": "CZ",
            "Ш": "SH",
            "Щ": "SCH",
            "Ъ": "",
            "Ы": "y",
            "Ь": "",
            "Э": "E",
            "Ю": "U",
            "Я": "YA",
            ",": "",
            "?": "",
            " ": "_",
            "~": "",
            "!": "",
            "@": "",
            "#": "",
            "$": "",
            "%": "",
            "^": "",
            "&": "",
            "*": "",
            "(": "",
            ")": "",
            "-": "",
            "=": "",
            "+": "",
            ":": "",
            ";": "",
            "<": "",
            ">": "",
            "'": "",
            '"': "",
            "\\": "",
            "/": "",
            "№": "",
            "[": "",
            "]": "",
            "{": "",
            "}": "",
            "ґ": "",
            "ї": "",
            "є": "",
            "Ґ": "g",
            "Ї": "i",
            "Є": "e",
            "—": ""}
        for key in dictionary:
            string = string.replace(key, dictionary[key])
        return string

    def check_var(url):
        """Возвращает True, если сегмент пути — плейсхолдер {name}."""
        if url.strip().startswith("{") and url.strip().endswith("}"):
            return True
        else:
            return False

    def generate_uuid():
        """Возвращает шестнадцатеричный UUID без дефисов."""
        result = str(uuid.uuid4().hex)
        return result

    def get_apps():
        """Список непосредственных подкаталогов apps/ (имена приложений)."""
        apps_root = Path(settings.PROJECT_DIR) / "apps"
        if not apps_root.is_dir():
            return []
        return sorted(p.name for p in apps_root.iterdir() if p.is_dir() and p.name != "__pycache__")

    def get_content_length(file_path):
        """Возвращает размер файла в байтах строкой (для заголовка Content-Length)."""
        result = str(os.stat(file_path).st_size)
        return result

    def parse_content_type(content_type):
        """Разбирает заголовок Content-Type на основной тип и кодировку."""
        content_type = content_type.lower()
        charset = "utf-8"
        content_type_args = content_type.split(";")

        for arg in content_type_args:
            arg = arg.strip()

            if arg.startswith("charset="):
                charset = arg.replace("charset=", "", 1)

        return content_type_args[0], charset

    def to_title_case(text):
        """Преобразует ключ HTTP_* из environ в вид заголовка Title-Case."""
        text = text.upper()
        text = re.sub(r"^HTTP_", "", text)
        splitted = [(w if w == "WWW" else w.title()) for w in text.split("_")]
        return "-".join(splitted)

    def maybe_encode(s, codec="ascii"):
        """Кодирует строку в байты указанной кодировки; байты возвращает без изменений."""
        return s.encode(codec) if isinstance(s, str) else s

    def to_rfc822(dt):
        """
        Форматирует datetime в строку даты по RFC 822 / RFC 1123 (английские имена).

        Args:
            dt: Время с временной зоной (ожидается UTC для корректной подписи GMT).

        Returns:
            Строка вида Sun, 06 Nov 1994 08:49:37 GMT.

        Notes:
            Не использует strftime, чтобы не зависеть от локали для имён дней и месяцев.
        """
        t = dt.utctimetuple()
        _m = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
        return "%s, %02d %s %04d %02d:%02d:%02d GMT" % (
            ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")[t[6]],
            t[2],
            _m[t[1] - 1],
            t[0],
            t[3],
            t[4],
            t[5])


# **********************************************************************
# ******************************** EMail *******************************
# **********************************************************************
class EMail:
    """Обёртка над SMTP для отправки простого HTML-сообщения."""

    def __init__(
        self,
        server="localhost",
        login="",
        password="",
        subject="",
        to="",
        message="",):
        self._server = server
        self._login = login
        self._password = password
        self.mail = smtplib.SMTP(server)
        try:
            self.mail.starttls()
        except smtplib.SMTPException:
            pass
        if login and password:
            self.mail.login(login, password)
        self.msg = email.message.Message()
        self.msg["Subject"] = subject
        self.msg["From"] = login or "noreply@localhost"
        self.msg["To"] = to
        self.msg.add_header("Content-Type", "text/html")
        self.msg.set_payload(message)

    def send(self):
        self.mail.sendmail(self.msg["From"], [self.msg["To"]], self.msg.as_string())
        self.mail.quit()


# **********************************************************************
# ******************************* Request ******************************
# **********************************************************************
class Request(object):
    """
    Контейнер данных входящего HTTP-запроса (словарь environ WSGI).

    Notes:
        Поля session, csrf_token, user_id и флаг csrf_failed заполняются
        middleware после разбора тела запроса.
    """
    def __init__(self, environ):
        self.environ = environ
        self.method = environ.get("REQUEST_METHOD", "GET").upper()
        self.path = (environ.get("PATH_INFO") or "/").strip() or "/"
        raw_ct = environ.get("CONTENT_TYPE") or ""
        self.content_type, self.charset = Utilities.parse_content_type(raw_ct or "application/octet-stream")
        self.headers = self.get_headers()
        self.context = {}
        self.args = {}

        try:
            content_length = int(environ.get("CONTENT_LENGTH") or 0)
        except (TypeError, ValueError):
            content_length = 0

        if content_length > 0:
            self.body = environ["wsgi.input"].read(content_length)
        else:
            self.body = b""

        qs = environ.get("QUERY_STRING", "") or ""
        self.raw_query_string = qs
        self.GET = flatten_parse_result(urllib.parse.parse_qs(qs, keep_blank_values=True))

        self.POST = {}
        self.FILES = {}
        ct_main = self.content_type.split(";")[0].strip().lower()

        if self.method in ("POST", "PUT", "PATCH", "DELETE"):
            if ct_main == "application/x-www-form-urlencoded":
                try:
                    decoded = self.body.decode(self.charset, errors="replace")
                except LookupError:
                    decoded = self.body.decode("utf-8", errors="replace")
                self.POST = flatten_parse_result(urllib.parse.parse_qs(decoded, keep_blank_values=True))
            elif ct_main == "multipart/form-data":
                boundary = ""
                for part in raw_ct.split(";")[1:]:
                    part = part.strip()
                    if part.lower().startswith("boundary="):
                        boundary = part.partition("=")[2].strip().strip('"')
                        break
                self.POST, self.FILES = parse_multipart_body(self.body, boundary, self.charset)

        self.session = {}
        self.session_id = None
        self.session_is_new = False
        self.csrf_token = ""
        self.user_id = None
        self.csrf_failed = False

    def __repr__(self):
        return f"<Request {self.method} - {self.path}>"

    def get_accept_encoding(self):
        raw = self.environ.get("HTTP_ACCEPT_ENCODING") or ""
        return [enc.strip().lower() for enc in raw.split(",") if enc.strip()]

    def get_cookies(self):
        jar = SimpleCookie()
        try:
            jar.load(self.environ.get("HTTP_COOKIE", ""))
        except Exception:
            return {}
        return {k: m.value for k, m in jar.items()}

    def get_content_length(self):
        return self.environ.get("CONTENT_LENGTH", "")

    def get_headers(self):
        headers = {}
        for key, value in self.environ.items():
            if not key.startswith("HTTP_"):
                continue
            name = Utilities.to_title_case(key)
            headers[name] = value
        return headers

    def get_etag(self):
        return (self.environ.get("HTTP_IF_NONE_MATCH") or "").strip('"')

    def get_query_string(self):
        """Возвращает необработанную строку запроса QUERY_STRING."""
        return self.raw_query_string

    def get_form(self):
        """Объединение GET и POST (плоские строки; файлы только в FILES)."""
        merged = dict(self.GET)
        merged.update(self.POST)
        return merged

    @property
    def is_authenticated(self):
        return self.user_id is not None


# **********************************************************************
# ******************************* Response *****************************
# **********************************************************************
class Response(object):
    """
    Исходящий HTTP-ответ для WSGI.

    Notes:
        Заголовки хранятся в виде словаря str -> str; несколько
        значений Set-Cookie задаются через словарь cookies.
    """
    def __init__(self):
        self.charset = "utf-8"
        self.cookies = {}
        self.headers = {"Content-Type": "text/html; charset=utf-8"}
        self.status_code = 200
        self.text = ""
        self.body = b""
        self.stream = None
        self.is_redirect = False

    def __repr__(self):
        code = int(self.status_code)
        phrase = STATUS_CODES.get(code, "Unknown")
        return f'<Response {code} - "{phrase}">'

    def redirect(self, url, status_code=302):
        """
        Настраивает редирект и возвращает этот же объект ответа.

        Args:
            url: Значение заголовка Location.
            status_code: Код ответа (по умолчанию 302).

        Returns:
            Текущий экземпляр Response для цепочки вызовов.
        """
        self.is_redirect = True
        self.status_code = int(status_code)
        self.headers = {"Content-Type": f"text/html; charset={self.charset}", "Location": url, "Content-Length": "0"}
        self.text = ""
        self.body = b""
        self.stream = None
        return self

    def wsgi_status(self):
        code = int(self.status_code)
        phrase = STATUS_CODES.get(code, "Unknown")
        return f"{code} {phrase}"

    def wsgi_headers(self):
        hdr_list = []
        for key, val in self.headers.items():
            hdr_list.append((key, str(val)))
        for name, val in self.cookies.items():
            if isinstance(val, dict):
                v = val.get("value", "")
                opts = {
                    k: w
                    for k, w in val.items()
                    if k != "value"}
                hdr_list.append(("Set-Cookie", build_set_cookie_value(name, v, **opts)))
            else:
                hdr_list.append(("Set-Cookie", build_set_cookie_value(name, val)))
        return hdr_list

    def wsgi_body_iter(self):
        if self.stream is not None:
            return self.stream
        ct = self.headers.get("Content-Type", "")
        if ct.startswith("text/") or "javascript" in ct:
            data = (self.text or "").encode(self.charset)
            return iter([data])
        if isinstance(self.body, (bytes, bytearray)):
            return iter([bytes(self.body)]) if self.body else iter([b""])
        if (
            self.body is not None
            and hasattr(self.body, "__iter__")
            and not isinstance(self.body, (str, bytes, bytearray))):
            return self.body
        return iter([b""])


# **********************************************************************
# ****************************** Middleware ****************************
# **********************************************************************
class Middleware:
    """
    Базовый класс WSGI-middleware с цепочкой process_* вокруг приложения.

    Notes:
        Внешний экземпляр вызывает dispatch_request у вложенного приложения.
    """
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        request = Request(environ)
        response = self.app.dispatch_request(request)

        if response.stream is None:
            payload = b"".join(response.wsgi_body_iter())
            if "Content-Length" not in response.headers:
                response.headers["Content-Length"] = str(len(payload))
            body_iter = iter([payload])
        else:
            body_iter = response.wsgi_body_iter()

        start_response(response.wsgi_status(), response.wsgi_headers())

        return body_iter

    def add(self, middleware_class, **kwargs):
        self.app = middleware_class(self.app, **kwargs)

    def process_request(self, request):
        pass

    def process_response(self, request, response):
        pass

    def dispatch_request(self, request):
        self.process_request(request)
        response = self.app.dispatch_request(request)
        self.process_response(request, response)
        return response


class TrustedHostMiddleware(Middleware):
    """Проверка HTTP Host по ALLOWED_HOSTS (для прода задайте явный список)."""
    def __call__(self, environ, start_response):
        allowed = getattr(settings, "ALLOWED_HOSTS", ["*"])
        if allowed not in (["*"], ("*",)):
            host = (environ.get("HTTP_HOST") or "").split(":")[0].strip().lower()
            ok = any(h.strip().lower() == host for h in allowed)
            if not ok:
                r = Response()
                r.status_code = 400
                r.headers["Content-Type"] = "text/plain; charset=utf-8"
                r.text = "Invalid Host header"
                start_response(r.wsgi_status(), r.wsgi_headers())
                return iter([r.text.encode(r.charset)])

        return Middleware.__call__(self, environ, start_response)


class RequestLimitsMiddleware(Middleware):
    """Лимит размера тела (CONTENT_LENGTH) и числа заголовков запроса."""
    def __call__(self, environ, start_response):
        try:
            cl = int(environ.get("CONTENT_LENGTH") or 0)
        except (TypeError, ValueError):
            cl = 0

        max_b = int(getattr(settings, "MAX_REQUEST_BODY_BYTES", 10_000_000))
        if cl > max_b:
            r = Response()
            r.status_code = 413
            r.headers["Content-Type"] = "text/plain; charset=utf-8"
            r.text = STATUS_CODES[413]
            start_response(r.wsgi_status(), r.wsgi_headers())
            return iter([b""])

        max_h = int(getattr(settings, "MAX_HTTP_HEADERS", 80))
        n = sum(1 for k in environ if k.startswith("HTTP_") or k in ("CONTENT_LENGTH", "CONTENT_TYPE"))
        if n > max_h:
            r = Response()
            r.status_code = 400
            r.headers["Content-Type"] = "text/plain; charset=utf-8"
            r.text = "Too many headers"
            start_response(r.wsgi_status(), r.wsgi_headers())
            return iter([b""])

        return Middleware.__call__(self, environ, start_response)


class RateLimitMiddleware(Middleware):
    """In-process лимит запросов в минуту на REMOTE_ADDR (0 = выкл.)."""
    def __call__(self, environ, start_response):
        lim = int(getattr(settings, "RATE_LIMIT_PER_MINUTE", 0) or 0)
        if lim <= 0:
            return Middleware.__call__(self, environ, start_response)

        ip = environ.get("REMOTE_ADDR") or "unknown"
        now = time.time()
        window = 60.0

        with _CACHE_LOCK:
            bucket = _RATE_BUCKET.setdefault(ip, [])
            bucket[:] = [t for t in bucket if now - t < window]
            if len(bucket) >= lim:
                r = Response()
                r.status_code = 429
                r.headers["Content-Type"] = "text/plain; charset=utf-8"
                r.text = STATUS_CODES[429]
                start_response(r.wsgi_status(), r.wsgi_headers())
                return iter([b""])
            bucket.append(now)

        return Middleware.__call__(self, environ, start_response)


class CorsMiddleware(Middleware):
    """CORS: ответ OPTIONS и заголовки по CORS_ORIGINS (пусто = выкл.)."""
    def _apply_cors(self, request, response, origins):
        origin = request.environ.get("HTTP_ORIGIN", "")
        if "*" in origins:
            allow = "*"
        elif origin and origin in origins:
            allow = origin
        elif origins:
            allow = origins[0]
        else:
            return

        response.headers["Access-Control-Allow-Origin"] = allow
        response.headers.setdefault(
            "Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD")
        req_hdr = request.environ.get("HTTP_ACCESS_CONTROL_REQUEST_HEADERS", "*")
        response.headers.setdefault("Access-Control-Allow-Headers", req_hdr or "*")
        response.headers.setdefault("Access-Control-Max-Age", "86400")

    def process_response(self, request, response):
        origins = list(getattr(settings, "CORS_ORIGINS", None) or [])
        if origins:
            self._apply_cors(request, response, origins)

    def dispatch_request(self, request):
        origins = list(getattr(settings, "CORS_ORIGINS", None) or [])
        if not origins:
            return Middleware.dispatch_request(self, request)

        if (
            request.method == "OPTIONS"
            and request.environ.get("HTTP_ACCESS_CONTROL_REQUEST_METHOD")):
            self.process_request(request)
            r = Response()
            r.status_code = 204
            r.headers["Content-Type"] = "text/plain; charset=utf-8"
            self.process_response(request, r)
            return r

        return Middleware.dispatch_request(self, request)


class ApiOriginMiddleware(Middleware):
    """Для API-префиксов: при API_ENFORCE_ORIGIN требует Origin из CORS_ORIGINS."""
    def dispatch_request(self, request):
        if not getattr(settings, "API_ENFORCE_ORIGIN", False):
            return Middleware.dispatch_request(self, request)

        path = request.path or ""
        prefs = getattr(settings, "API_PATH_PREFIXES", ("/api",))
        if not any(path.startswith(p) for p in prefs):
            return Middleware.dispatch_request(self, request)

        if request.method in CSRF_SAFE_METHODS:
            return Middleware.dispatch_request(self, request)

        allowed = list(getattr(settings, "CORS_ORIGINS", None) or [])
        origin = request.environ.get("HTTP_ORIGIN", "")
        ref = request.environ.get("HTTP_REFERER", "")
        ok = False
        if origin and origin in allowed:
            ok = True
        elif ref and allowed:
            ok = any(ref.startswith(a + "/") or ref.rstrip("/") == a for a in allowed)

        if not ok:
            self.process_request(request)
            r = Response()
            r.status_code = 403
            r.headers["Content-Type"] = "text/plain; charset=utf-8"
            r.text = "Origin/Referer not allowed"
            self.process_response(request, r)
            return r

        return Middleware.dispatch_request(self, request)


class MetricsMiddleware(Middleware):
    """Добавляет X-Response-Time-Ms (время обработки внутри цепочки под этим слоем)."""
    def dispatch_request(self, request):
        t0 = time.perf_counter()
        response = Middleware.dispatch_request(self, request)
        ms = (time.perf_counter() - t0) * 1000.0
        response.headers.setdefault("X-Response-Time-Ms", f"{ms:.3f}")
        return response


class HstsMiddleware(Middleware):
    """Strict-Transport-Security только при HTTPS (wsgi.url_scheme)."""
    def process_response(self, request, response):
        if request.environ.get("wsgi.url_scheme") != "https":
            return

        age = int(getattr(settings, "HSTS_MAX_AGE", 31536000))
        val = f"max-age={age}"
        if getattr(settings, "HSTS_INCLUDE_SUBDOMAINS", False):
            val += "; includeSubDomains"
        response.headers.setdefault("Strict-Transport-Security", val)


class SensitiveCacheMiddleware(Middleware):
    """Cache-Control: no-store для ошибок, чувствительных путей и авторизованных."""
    def process_response(self, request, response):
        path = request.path or ""
        prefs = getattr(settings, "SENSITIVE_CACHE_PATH_PREFIXES", ("/api",))
        code = int(response.status_code)

        if (
            code >= 400
            or getattr(request, "user_id", None) is not None
            or any(path.startswith(p) for p in prefs)):
            response.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate")


class ApiVersionPrefixMiddleware(Middleware):
    """Срезает API_VERSION_PREFIX с начала path (версионирование в URL)."""
    def process_request(self, request):
        prefix = getattr(settings, "API_VERSION_PREFIX", "") or ""
        if not prefix or not request.path.startswith(prefix):
            return

        rest = request.path[len(prefix) :].lstrip("/")
        request.path = "/" + rest if rest else "/"


class IdempotencyMiddleware(Middleware):
    """Кэш ответа POST по заголовку Idempotency-Key (in-process, IDEMPOTENCY_TTL)."""
    def dispatch_request(self, request):
        if request.method != "POST":
            return Middleware.dispatch_request(self, request)

        key = (request.environ.get("HTTP_IDEMPOTENCY_KEY") or "").strip()
        if not key:
            return Middleware.dispatch_request(self, request)

        ttl = int(getattr(settings, "IDEMPOTENCY_TTL", 3600))
        ck = f"POST|{request.path}|{key}"
        now = time.time()

        with _CACHE_LOCK:
            ent = _IDEMPOTENCY_CACHE.get(ck)
            if ent and ent[0] > now:
                self.process_request(request)
                _, status, hdrs, text = ent
                r = Response()
                r.status_code = status
                r.headers.update(hdrs)
                r.text = text
                self.process_response(request, r)
                return r

        request._idempotency_ck = ck
        request._idempotency_ttl = ttl
        return Middleware.dispatch_request(self, request)

    def process_response(self, request, response):
        ck = getattr(request, "_idempotency_ck", None)
        if not ck:
            return

        if int(response.status_code) >= 500:
            return

        with _CACHE_LOCK:
            _IDEMPOTENCY_CACHE[ck] = (
                time.time() + request._idempotency_ttl,
                int(response.status_code),
                dict(response.headers),
                response.text)


class ResponseCacheMiddleware(Middleware):
    """Простой кэш GET-ответов (RESPONSE_CACHE_TTL секунд, 0 = выкл.)."""
    def dispatch_request(self, request):
        ttl = int(getattr(settings, "RESPONSE_CACHE_TTL", 0) or 0)
        ck = None
        now = time.time()

        if ttl > 0 and request.method == "GET":
            ck = f"{request.path}?{request.environ.get('QUERY_STRING', '')}"
            with _CACHE_LOCK:
                ent = _RESPONSE_CACHE.get(ck)
                if ent and ent[0] > now:
                    self.process_request(request)
                    _, status, hdrs, text = ent
                    r = Response()
                    r.status_code = status
                    r.headers.update(hdrs)
                    r.text = text
                    self.process_response(request, r)
                    return r

        response = Middleware.dispatch_request(self, request)

        if (
            ttl > 0
            and ck
            and request.method == "GET"
            and int(response.status_code) == 200
            and response.stream is None):
            with _CACHE_LOCK:
                _RESPONSE_CACHE[ck] = (
                    time.time() + ttl,
                    int(response.status_code),
                    dict(response.headers),
                    response.text)

        return response


class RequestHooksMiddleware(Middleware):
    """Хуки BEFORE_REQUEST_HOOKS(request) и AFTER_REQUEST_HOOKS(request, response)."""
    def dispatch_request(self, request):
        for hook in getattr(settings, "BEFORE_REQUEST_HOOKS", None) or []:
            hook(request)

        response = self.app.dispatch_request(request)

        for hook in getattr(settings, "AFTER_REQUEST_HOOKS", None) or []:
            hook(request, response)

        return response


class AuthenticationMiddleware(Middleware):
    """Читает идентификатор пользователя из сессии (ключ AUTH_SESSION_KEY)."""
    def process_request(self, request):
        key = getattr(settings, "AUTH_SESSION_KEY", "auth_user_id")
        uid = request.session.get(key)
        request.user_id = uid if uid is not None else None

    def process_response(self, request, response):
        pass


class CleanHTMLMiddleware(Middleware):
    """Зарезервировано: очистка или нормализация HTML в ответе."""

    def __init__(self, app, compress_level=6):
        super().__init__(app)
        self.compress_level = compress_level

    def process_request(self, request):
        pass

    def process_response(self, request, response):
        pass


class CsrfMiddleware(Middleware):
    """Проверка CSRF для небезопасных методов (токен в сессии)."""

    def process_request(self, request):
        tok = request.session.get("_csrf_token")

        if not tok:
            tok = secrets.token_urlsafe(32)
            request.session["_csrf_token"] = tok

        request.csrf_token = tok

        if request.method in CSRF_SAFE_METHODS:
            return

        hdr = getattr(settings, "CSRF_HEADER_NAME", "X-CSRF-Token")
        env_key = "HTTP_" + hdr.upper().replace("-", "_")
        sent = (
            request.POST.get("csrf_token")
            or request.POST.get("csrfmiddlewaretoken")
            or request.environ.get(env_key, ""))

        if not sent or len(str(sent)) != len(str(request.csrf_token)):
            request.csrf_failed = True
            return

        if not hmac.compare_digest(
            str(sent).encode("utf-8"), str(request.csrf_token).encode("utf-8")):
            request.csrf_failed = True

    def dispatch_request(self, request):
        self.process_request(request)

        if getattr(request, "csrf_failed", False):
            response = Response()
            response.status_code = 403
            response.headers["Content-Type"] = "text/plain; charset=utf-8"
            response.text = "CSRF verification failed"
            self.process_response(request, response)
            return response

        response = self.app.dispatch_request(request)
        self.process_response(request, response)
        return response


class GzipMiddleware(Middleware):
    """Зарезервировано: сжатие тела ответа в gzip при поддержке клиентом."""

    def __init__(self, app, compress_level=6):
        super().__init__(app)
        self.compress_level = compress_level
        self.zipped = {}

    def process_request(self, request):
        pass

    def process_response(self, request, response):
        pass


class LogMiddleware(Middleware):
    """Структурный лог запроса/ответа в stderr (log_event)."""
    def __init__(self, app):
        super().__init__(app)

    def process_response(self, request, response):
        log_event(
            "http_access",
            method=request.method,
            path=request.path,
            status=int(response.status_code),
            remote_addr=request.environ.get("REMOTE_ADDR"))


class MessageMiddleware(Middleware):
    """Логирование ответа и подстановка шаблонов ошибок."""

    def process_response(self, request, response):
        code = int(response.status_code)
        if code == 200:
            Messages.info_response(request, response)
        elif code in (301, 302, 303, 307, 308):
            Messages.info_response(request, response)
        elif code == 404:
            Messages.error_response(request, response)
            response.text = render("errors/404.html")
        elif code == 500:
            Messages.error_response(request, response)
            response.text = render("errors/500.html")
        elif code == 501:
            Messages.error_response(request, response)
            response.text = render("errors/501.html", method=f"{request.method.upper()}")


class SecurityMiddleware(Middleware):
    """Заголовки безопасности по умолчанию (строгий базовый набор)."""

    def process_response(self, request, response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")


class SessionMiddleware(Middleware):
    """
    Cookie-сессия; данные хранятся в памяти процесса (SESSION_STORE).

    Notes:
        Хранилище не разделяется между отдельными worker-процессами WSGI.
    """
    def process_request(self, request):
        name = getattr(settings, "SESSION_COOKIE_NAME", "stonecrab_sid")
        sid = request.get_cookies().get(name)
        if sid and sid in SESSION_STORE:
            request.session_id = sid
            request.session = SESSION_STORE[sid]
            request.session_is_new = False
        else:
            sid = secrets.token_urlsafe(24)
            request.session_id = sid
            request.session = {}
            SESSION_STORE[sid] = request.session
            request.session_is_new = True

    def process_response(self, request, response):
        if getattr(request, "session_is_new", False):
            name = getattr(settings, "SESSION_COOKIE_NAME", "stonecrab_sid")
            sec = getattr(settings, "SESSION_COOKIE_SECURE", None)
            if sec is None:
                sec = request.environ.get("wsgi.url_scheme") == "https"
            samesite = getattr(settings, "SESSION_COOKIE_SAMESITE", "Lax")
            response.cookies[name] = {
                "value": request.session_id,
                "secure": bool(sec),
                "samesite": samesite,
                "httponly": True,
                "path": "/"}


class StaticfilesMiddleware(Middleware):
    """Раздача STATIC_DIR и MEDIA_DIR по префиксам из настроек."""

    def __init__(self, app, block_size=16 * 4096):
        super().__init__(app)
        self.block_size = block_size

    def process_response(self, request, response):
        path = request.path.lstrip("/") or ""
        parts = path.split("/", 1)
        if not parts or not parts[0]:
            return
        first = parts[0]
        static_url = settings.STATIC_URL.strip("/")
        media_url = settings.MEDIA_URL.strip("/")
        static_root = os.path.realpath(settings.STATIC_DIR)
        media_root = os.path.realpath(settings.MEDIA_DIR)
        rel = ""
        base = None
        if first == static_url:
            base = static_root
            rel = parts[1] if len(parts) > 1 else ""
        elif first == media_url:
            base = media_root
            rel = parts[1] if len(parts) > 1 else ""
        else:
            return

        rel = rel.replace("\\", "/")
        if ".." in rel.split("/"):
            response.status_code = 403
            response.headers["Content-Type"] = "text/plain; charset=utf-8"
            response.text = "Forbidden"
            response.stream = None
            return

        file_path = os.path.realpath(os.path.join(base, rel))
        if not file_path.startswith(base + os.sep) and file_path != base:
            response.status_code = 403
            response.headers["Content-Type"] = "text/plain; charset=utf-8"
            response.text = "Forbidden"
            response.stream = None
            return

        if request.method not in ("HEAD", "GET"):
            response.status_code = 405
            response.headers["Content-Type"] = f"text/plain; charset={request.charset}"
            response.text = ""
            response.stream = None
            return

        if not os.path.isfile(file_path):
            return

        file_name = os.path.basename(file_path)
        mime_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"
        response.status_code = 200
        response.stream = None
        response.headers["Accept-Ranges"] = "bytes"
        response.headers["Content-Length"] = Utilities.get_content_length(file_path)
        response.headers["Last-Modified"] = Utilities.HTTP.generate_last_modified(file_path)
        etag = Utilities.HTTP.get_etag(file_path)
        response.headers["ETag"] = etag

        if mime_type.startswith("text") or mime_type == "application/javascript":
            response.headers["Content-Type"] = f"{mime_type}; charset={request.charset}"
            with open(file_path, "r", encoding=request.charset, errors="replace") as fh:
                response.text = fh.read()
            if request.method == "HEAD":
                response.text = ""
        else:
            response.headers["Content-Type"] = mime_type
            inm = request.get_etag()
            etag_cmp = etag.strip('"')
            if inm and inm == etag_cmp:
                response.status_code = 304
                response.headers.pop("Content-Length", None)
                response.text = ""
                response.body = b""
                return
            if request.method == "HEAD":
                response.text = ""
                response.body = b""
                response.stream = None
            else:
                fh = open(file_path, "rb")
                response.text = ""
                response.stream = self.iter_and_close_file(fh)

    def iter_and_close_file(self, fh):
        """
        Читает открытый бинарный файл блоками и закрывает дескриптор после чтения.

        Args:
            fh: Открытый файловый объект в режиме "rb".

        Yields:
            Фрагменты байтов длиной до block_size.
        """
        try:
            while True:
                block = fh.read(self.block_size)
                if not block:
                    break
                yield block
        finally:
            fh.close()


# **********************************************************************
# ******************************* StoneCrab ****************************
# **********************************************************************
class StoneCrab:
    """
    Основное WSGI-приложение: маршруты из apps/*, цепочка middleware.

    Notes:
        Экземпляр вызывается сервером как application(environ, start_response).
    """
    def __init__(self):
        self.apps_list = Utilities.get_apps()
        self.middleware = Middleware(self)
        self.routes = self.register_apps_routes()
        self.session = None
        for item in reversed(settings.MIDDLEWARE):
            get_class = lambda x: globals()[x]
            c = get_class(item)
            self.middleware.add(c)

    def __call__(self, environ, start_response):
        """
        WSGI-интерфейс приложения: передаёт запрос в цепочку middleware.

        Args:
            environ: Словарь окружения WSGI.
            start_response: Колбэк PEP 3333 для старта ответа.

        Returns:
            Итератор байтовых фрагментов тела ответа.
        """
        return self.middleware(environ, start_response)

    def default_response(self, response):
        """
        Заполняет ответ телом «не найдено» и кодом 404.

        Args:
            response: Экземпляр Response.
        """
        response.status_code = 404
        response.headers.setdefault("Content-Type", f"text/plain; charset={response.charset}")
        response.text = STATUS_CODES[404]

    def dispatch_request(self, request):
        """
        Находит обработчик по пути, вызывает его и возвращает Response.

        Args:
            request: Текущий Request.

        Returns:
            Сформированный Response.
        """
        hp = getattr(settings, "HEALTH_PATH", "/health")
        op = getattr(settings, "OPENAPI_PATH", "/openapi.json")

        if request.path == hp:
            r = Response()
            r.headers["Content-Type"] = "application/json; charset=utf-8"
            r.text = json.dumps({"status": "ok"})
            return r

        if request.path == op:
            r = Response()
            r.headers["Content-Type"] = "application/json; charset=utf-8"
            r.text = json.dumps(build_openapi_spec(self.routes))
            return r

        response = Response()
        handler, kwargs = self.find_handler(request_path=request.path)

        if handler is not None:
            allowed = getattr(handler, STONE_CRAB_METHODS, None)

            if (
                isclass(handler)
                and allowed is not None
                and request.method not in allowed):
                response.status_code = 405
                response.headers.setdefault("Content-Type", f"text/plain; charset={response.charset}")
                response.text = STATUS_CODES[405]
                return response

            if isclass(handler):
                view_method = getattr(handler(), request.method.lower(), None)
                if view_method is None:
                    Messages.error_method_not_detected(request)
                    response.status_code = 501
                    response.text = STATUS_CODES[501]
                    return response
                handler = view_method

            result = handler(request, response, **kwargs)

            if isinstance(result, Response):
                return result

            if result is not None:
                response.text = str(result)
                response.status_code = 200

            return response

        self.default_response(response)

        return response

    def find_handler(self, request_path):
        """
        Ищет обработчик и именованные группы для request_path.

        Args:
            request_path: Путь из запроса.

        Returns:
            Кортеж (handler, kwargs) или (None, None).
        """

        for path, handler in self.routes.items():
            parse_result = Utilities.URL.parse(path, request_path)
            if parse_result["status"]:
                return handler, parse_result["variables"]
        return None, None

    def register_apps_routes(self):
        """
        Собирает маршруты из apps.<имя>.routes (urls) и из @route в views.

        Raises:
            SystemExit: При дублировании полного пути маршрута.
        """
        prefix = None
        routes = {}

        for app in self.apps_list:
            prefix = Utilities.URL.get_url_prefix(app)
            module = __import__(f"apps.{app}.routes", fromlist=["object"])

            for path in module.urls:
                handler = module.urls[path]
                path = Utilities.URL.add_slash(path)
                full_path = f"{prefix}{path}"

                try:
                    assert full_path not in routes
                except AssertionError:
                    Messages.error_route_already_exists(full_path)
                    sys.exit()

                routes[full_path] = handler

            views_module = None

            try:
                views_module = __import__(f"apps.{app}.views", fromlist=["object"])
            except ImportError:
                views_module = None

            if views_module is None:
                continue

            for name in dir(views_module):
                if name.startswith("_"):
                    continue

                obj = getattr(views_module, name)

                if not hasattr(obj, STONE_CRAB_ROUTE):
                    continue

                if not (isfunction(obj) or isclass(obj)):
                    continue

                raw_path = getattr(obj, STONE_CRAB_ROUTE)
                path = Utilities.URL.add_slash(raw_path)
                full_path = f"{prefix}{path}"
                handler = obj

                if not isclass(handler):
                    methods = getattr(handler, STONE_CRAB_METHODS, frozenset())
                    handler = wrap_view_method_guard(handler, methods)

                try:
                    assert full_path not in routes
                except AssertionError:
                    Messages.error_route_already_exists(full_path)
                    sys.exit()

                routes[full_path] = handler

        return routes


class View(object):
    """
    Базовый класс представления с методами по HTTP-глаголам (заглушки 501).

    Notes:
        Наследники переопределяют нужные методы; диспетчер вызывает
        get, post и т.д. в зависимости от request.method.
    """
    def __init__(self):
        pass

    def connect(self, request, response):
        response.status_code = 501

    def delete(self, request, response):
        response.status_code = 501

    def get(self, request, response):
        response.status_code = 501

    def head(self, request, response):
        response.status_code = 501

    def options(self, request, response):
        response.status_code = 501

    def patch(self, request, response):
        response.status_code = 501

    def post(self, request, response):
        response.status_code = 501

    def put(self, request, response):
        response.status_code = 501
        response.text = STATUS_CODES[501]

    def trace(self, request, response):
        response.status_code = 501


# **********************************************************************
# ***************************** Templating *****************************
# **********************************************************************
tokens = {
    "block_start": "{%",
    "block_end": "%}",
    "comment_start": "{#",
    "comment_end": "#}",
    "var_start": "{{",
    "var_end": "}}"}

types = {
    "comment": 0,
    "open_block": 1,
    "close_block": 2,
    "extends": 3,
    "static": 4,
    "text": 5,
    "var": 6}


operator_lookup_table = {
    "<": operator.lt,
    ">": operator.gt,
    "==": operator.eq,
    "!=": operator.ne,
    "<=": operator.le,
    ">=": operator.ge}


def eval_expression(expr):
    """
    Определяет, является ли выражение литералом или именем переменной шаблона.

    Args:
        expr: Строка из тега шаблона.

    Returns:
        Кортеж (kind, value), где kind — literal или name.
    """
    try:
        return "literal", ast.literal_eval(expr)
    except ValueError:
        return "name", expr
    except SyntaxError:
        return "name", expr


def resolve(name, context):
    """
    Разрешает путь переменной в контексте (точечная нотация и префикс ..).

    Args:
        name: Имя или путь вида a.b.c.
        context: Словарь контекста шаблона.

    Returns:
        Значение по пути; при отсутствии ключа пишет в лог и возвращает None.
    """
    if name.startswith(".."):
        context = context.get("..", {})
        name = name[2:]
    try:
        for tok in name.split("."):
            context = context[tok]
        return context
    except KeyError:
        Messages.out_error("KeyError")


class Base(object):
    """
    Базовый узел синтаксического дерева шаблона.

    Notes:
        Подклассы реализуют render для вывода фрагмента HTML.
    """
    def __init__(self, fragment=None):
        self.fragment = fragment

    def clean(self):
        """Убирает ограничители тега и лишние пробелы вокруг содержимого."""
        return self.fragment.strip()[2:-2].strip()

    def get_type(self):
        pass

    def process_fragment(self, fragment):
        """
        Дополнительный разбор текста фрагмента (переопределяется в подклассах).

        Args:
            fragment: Исходный текст узла.
        """
        pass

    def render(self):
        """Возвращает HTML-представление узла."""
        pass


class Comment(Base):
    """Узел комментария шаблона (в вывод не попадает)."""

    def __str__(self):
        return "Comment"

    def get_type(self):
        return "comment"

    def render(self):
        return ""


class Extends(Base):
    """Узел директивы наследования шаблона (зарезервировано)."""

    def __str__(self):
        return "Extends"

    def clean(self):
        return self.fragment.strip()[7:].strip()

    def render(self):
        return ""


class Static(Base):
    """Узел тега статического URL (префикс /static/)."""

    def __str__(self):
        return self.render()

    def clean(self):
        return self.fragment.strip()[6:].strip().strip('"').strip("'")

    def render(self):
        link = "/static/" + self.clean()
        return link


class Text(Base):
    """Узел неформатированного текста."""

    def __str__(self):
        return "Text"

    def process_fragment(self, fragment):
        self.text = fragment

    def render(self):
        return self.fragment


class Variable(Base):
    """Узел подстановки переменной {{ name }} из контекста."""

    def __init__(self, fragment=None, *args, **kwargs):
        self.args = args
        self.fragment = fragment
        self.fragment = self.clean()

    def __str__(self):
        return "Variable"

    def process_fragment(self, fragment):
        self.name = fragment

    def render(self):
        if self.args:
            for item in self.args:
                if type(item) == dict:
                    for key in item:
                        if self.fragment == key:
                            self.fragment = item[key]
                elif type(item) == tuple:
                    for value in item:
                        if type(value) == dict:
                            for key in value:
                                if self.fragment == key:
                                    self.fragment = value[key]
                else:
                    Messages.out_error("Variable: ожидался dict или tuple с dict в контексте")
        return str(self.fragment)


class Block(Base):
    """Узел открытия блока {% block %} (заглушка компилятора)."""

    def __str__(self):
        return "Block"

    def process_fragment(self, fragment):
        self.text = fragment

    def render(self):
        return self.fragment


class EndBlock(Base):
    """Узел закрытия блока {% endblock %} (заглушка компилятора)."""

    def __str__(self):
        return "EndBlock"

    def process_fragment(self, fragment):
        self.text = fragment

    def render(self):
        return self.fragment


class If(Base):
    """Узел условия {% if %} (заглушка компилятора)."""

    def __str__(self):
        return "If"

    def process_fragment(self, fragment):
        self.text = fragment

    def render(self):
        return self.fragment


class Else(Base):
    """Узел ветки {% else %} (заглушка компилятора)."""

    def __str__(self):
        return "Else"

    def process_fragment(self, fragment):
        self.text = fragment

    def render(self):
        return self.fragment


class Elif(Base):
    """Узел ветки {% elif %} (заглушка компилятора)."""

    def __str__(self):
        return "Elif"

    def process_fragment(self, fragment):
        self.text = fragment

    def render(self):
        return self.fragment


regex_tokens = tuple(token for token in tokens.values())
TOK_REGEX = re.compile(r"(%s.*?%s|%s.*?%s|%s.*?%s)" % regex_tokens)


class Fragment(object):
    """Фрагмент исходного текста шаблона с определением типа лексемы."""

    def __init__(self, raw_text):
        self.raw = raw_text
        self.clean = self.clean_fragment()

    def clean_fragment(self):
        if self.raw[:2] in tokens["block_start"]:
            return self.raw.strip()[2:-2].strip()
        return self.raw

    def get_raw(self):
        return self.raw

    @property
    def type(self):
        raw_start = self.raw[:2]
        if raw_start == tokens["comment_start"]:
            return types["comment"]
        elif raw_start == tokens["var_start"]:
            return types["var"]
        elif raw_start == tokens["block_start"]:
            if self.clean[:3] == "end":
                return types["close_block"]
            elif self.clean[:6] == "static":
                return types["static"]
            elif self.clean[:7] == "extends":
                return types["extends"]
            else:
                return types["open_block"]
        else:
            return types["text"]


class Compiler(object):
    """
    Компилятор шаблонов: разбор текста в узлы и склейка HTML.

    Args:
        template: Имя файла шаблона относительно TEMPLATE_DIRS.

    Notes:
        Дополнительные позиционные и именованные аргументы передаются в узлы
        переменных (например, render("x.html", key=value)).
    """
    def __init__(self, template: str, *args, **kwargs):
        self.args = args
        self.template_name = template
        self.kwargs = kwargs

    def compile(self):
        """
        Выполняет разбор шаблона и возвращает итоговую HTML-строку.

        Returns:
            Собранный HTML без потоковой отдачи.
        """
        self.template = self.open_file(self.get_template_path())
        nodes = []
        new_node = []
        for fragment in self.each_fragment():
            if fragment.type == types["open_block"]:
                new_node.append(self.create_node(fragment))
                continue
            elif fragment.type == types["close_block"]:
                new_node.append(self.create_node(fragment))
                nodes.append(new_node)
                new_node = []
            else:
                node = self.create_node(fragment)
                nodes.append(node)

        html = ""
        for node in nodes:
            if type(node) == list:
                pass
            else:
                html += node.render()
        return html

    def create_node(self, fragment):
        node_class = None
        if fragment.type == types["comment"]:
            node_class = Comment
        elif fragment.type == types["open_block"]:
            cmd = fragment.clean.split()[0]
            node_class = Text
            if cmd == "block":
                node_class = Block
            elif cmd == "if":
                node_class = If
            elif cmd == "else":
                node_class = Else
            elif cmd == "elif":
                node_class = Elif
        elif fragment.type == types["extends"]:
            node_class = Extends
        elif fragment.type == types["close_block"]:
            node_class = EndBlock
        elif fragment.type == types["static"]:
            node_class = Static
        elif fragment.type == types["text"]:
            node_class = Text
        elif fragment.type == types["var"]:
            node_class = Variable
            return node_class(fragment.clean, self.args, self.kwargs)
        if node_class is None:
            return Text(fragment.clean)
        return node_class(fragment.clean)

    def each_fragment(self):
        """Итерирует по фрагментам исходного текста, отделяемым тегами шаблона."""
        for fragment in TOK_REGEX.split(self.template):
            if fragment:
                yield Fragment(fragment)

    def get_template_path(self):
        """Абсолютный путь к файлу шаблона в каталоге TEMPLATE_DIRS."""
        base = getattr(settings, "TEMPLATE_DIRS", os.path.join(os.getcwd(), "templates"))
        return os.path.join(os.path.abspath(base), self.template_name)

    def open_file(self, path):
        """Читает файл шаблона в одну строку Unicode."""

        with open(path, encoding="utf-8") as file:
            html = file.read()
            return html


def render(template: str, *args, **kwargs):
    """
    Собирает HTML по имени файла шаблона и контексту.

    Args:
        template: Путь к файлу относительно settings.TEMPLATE_DIRS.
        *args: Дополнительные позиционные аргументы для узлов переменных.
        **kwargs: Именованный контекст для подстановок {{ }}.

    Returns:
        Строка с готовым HTML.
    """
    return Compiler(template, *args, **kwargs).compile()


# **********************************************************************
# ****************************** Management ****************************
# **********************************************************************
class Management:
    """
    CLI-команды startproject и startapp для генерации файлов проекта.

    Notes:
        Запуск: python stonecrab.py startproject из целевого каталога.
    """
    def __init__(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        startapp = subparsers.add_parser("startapp")
        startapp.add_argument("name")
        startproject = subparsers.add_parser("startproject")
        runserver = subparsers.add_parser("runserver")
        runserver.add_argument("--host", default="127.0.0.1")
        runserver.add_argument("--port", type=int, default=8000)
        self.parser = parser

    def create_errors_html_pages(self):
        """Минимальные HTML-шаблоны ошибок (без внешних фрагментов)."""

        def page(title, body_extra=""):
            return (
                '<!DOCTYPE html><html lang="en"><head>'
                '<meta charset="utf-8"><title>%s</title></head><body>'
                "<h1>%s</h1>%s</body></html>") % (title, title, body_extra)

        Utilities.FileSystem.create_file(name="templates/errors/404.html", content=page("404 Not Found"))
        Messages.info_create_file("templates/errors/404.html")
        Utilities.FileSystem.create_file(name="templates/errors/500.html", content=page("500 Internal Server Error"))
        Messages.info_create_file("templates/errors/500.html")
        Utilities.FileSystem.create_file(
            name="templates/errors/501.html",
            content=page("501 Not Implemented", "<p>Method: {{ method }}</p>"))
        Messages.info_create_file("templates/errors/501.html")

    def create_settings(self):
        """Создаёт пакет settings/: __init__.py, base.py, development.py, production.py."""
        Utilities.FileSystem.create_folder("settings")
        Utilities.FileSystem.create_file(name="settings/__init__.py", content=SETTINGS_INIT_PY)
        Messages.info_create_file("settings/__init__.py")
        Utilities.FileSystem.create_file(name="settings/base.py", content=SETTINGS_BASE_PY)
        Messages.info_create_file("settings/base.py")
        Utilities.FileSystem.create_file(name="settings/development.py", content=SETTINGS_DEVELOPMENT_PY)
        Messages.info_create_file("settings/development.py")
        Utilities.FileSystem.create_file(name="settings/production.py", content=SETTINGS_PRODUCTION_PY)
        Messages.info_create_file("settings/production.py")

    def create_wsgi(self):
        """Создаёт wsgi.py: STONECRAB_ENV=production по умолчанию для воркера."""
        wsgi_body = (
            "import os\n"
            'os.environ.setdefault("STONECRAB_ENV", "production")\n\n'
            "from stonecrab import StoneCrab\n\n"
            "application = StoneCrab()\n")
        Utilities.FileSystem.create_file(name="wsgi.py", content=wsgi_body)
        Messages.info_create_file("wsgi.py")

    def startapp(self, name, url_prefix=None):
        """
        Создаёт пакет apps/<name>/ с routes.py и views.py.

        Args:
            name: Имя приложения (имя каталога).
            url_prefix: Префикс URL; по умолчанию /<name>/.

        Raises:
            FileNotFoundError: Если каталог apps отсутствует.
        """
        try:
            apps_name = f"apps/{name}"
            Utilities.FileSystem.create_folder(apps_name)
            Utilities.FileSystem.create_file(name=f"{apps_name}/__init__.py")
            if url_prefix == None:
                url_prefix = f"/{name}/"
            Utilities.FileSystem.create_file(
                name=f"{apps_name}/routes.py",
                content=(
                    f"from . import views\n\n"
                    f"URL_PREFIX = '{url_prefix}'\n\nurls = {{}}\n"))
            Utilities.FileSystem.create_file(f"{apps_name}/views.py")
            Messages.info_create_app(name)
        except FileNotFoundError:
            Messages.error_no_found_apps_folder()

    def update_app_index(self):
        """
        Заполняет приложение index маршрутом /, представлением и шаблоном.

        Notes:
            Вызывается из startproject после startapp(..., index).
        """
        Utilities.FileSystem.create_file(name="apps/index/views.py", content=views_template)
        Utilities.FileSystem.create_file(name="apps/index/routes.py", content=routes_template)
        index_html = (
            '<!DOCTYPE html><html lang="en"><head>'
            '<meta charset="utf-8"><title>{{ title }}</title></head>'
            "<body><h1>{{ title }}</h1>"
            "<p>{{ welcom }}</p><p>{{ version }}</p></body></html>")
        Utilities.FileSystem.create_file(name="templates/index.html", content=index_html)
        Messages.info_upd_app("index")

    def startproject(self):
        """
        Создаёт каркас проекта: каталоги, пакет settings/, wsgi.py, приложение index.

        Raises:
            OSError: При ошибках создания файловой системы (права, занятый путь).
        """
        Utilities.FileSystem.create_folder("apps")
        Messages.info_create_folder("apps")
        Utilities.FileSystem.create_folder("media")
        Messages.info_create_folder("media")
        Utilities.FileSystem.create_folder("static")
        Messages.info_create_folder("static")
        Utilities.FileSystem.create_folder("static/css")
        Messages.info_create_folder("static/css")
        Utilities.FileSystem.create_folder("static/fonts")
        Messages.info_create_folder("static/fonts")
        Utilities.FileSystem.create_folder("static/img")
        Messages.info_create_folder("static/img")
        Utilities.FileSystem.create_folder("static/js")
        Messages.info_create_folder("static/js")
        Utilities.FileSystem.create_folder("templates")
        Messages.info_create_folder("templates")
        Utilities.FileSystem.create_folder("templates/errors")
        Messages.info_create_folder("templates/errors")
        self.create_errors_html_pages()
        Utilities.FileSystem.create_file(name="static/css/stonecrab.css", content="")
        Messages.info_create_file("static/css/stonecrab.css")
        self.create_settings()
        self.create_wsgi()
        self.startapp(name="index", url_prefix="")
        self.update_app_index()


def run_dev_server(host="127.0.0.1", port=8000):
    """
    Встроенный dev-сервер (wsgiref).

    Окружение конфигурации — как при импорте settings (см. STONECRAB_ENV в settings/__init__.py).
    """
    from wsgiref.simple_server import make_server

    app = StoneCrab()
    srv = make_server(host, port, app)
    log_event("dev_server_start", host=host, port=port)
    srv.serve_forever()


if __name__ == "__main__":
    management = Management()
    namespace = management.parser.parse_args(sys.argv[1:])

    if namespace.command:
        if namespace.command == "startapp":
            management.startapp(name=namespace.name)
        elif namespace.command == "startproject":
            management.startproject()
        elif namespace.command == "runserver":
            run_dev_server(host=namespace.host, port=namespace.port)
        else:
            Messages.error_unknown_parameter()
    else:
        Messages.error_no_parameter()
