# -*- coding: utf-8 -*-
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
