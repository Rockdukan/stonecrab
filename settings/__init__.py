# -*- coding: utf-8 -*-
import os

_env = os.environ.get("STONECRAB_ENV", "development").lower()
if _env == "production":
    from .production import *  # noqa: F401,F403
else:
    from .development import *  # noqa: F401,F403
