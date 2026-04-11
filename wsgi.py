import os
os.environ.setdefault("STONECRAB_ENV", "production")

from stonecrab import StoneCrab

application = StoneCrab()
