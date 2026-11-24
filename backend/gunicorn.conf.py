"""Gunicorn configuration for the independent Search Admin FastAPI backend.

Start from `backend/` with:
    gunicorn -c gunicorn.conf.py app.main:app
"""
from __future__ import annotations

import os

worker_class = "uvicorn.workers.UvicornWorker"
workers = int(os.getenv("WEB_CONCURRENCY", "1"))

_raw_port = os.getenv("PORT", "8004")
try:
    _port = int(_raw_port)
    if not 1 <= _port <= 65535:
        raise ValueError
except ValueError as exc:
    raise RuntimeError(f"Invalid PORT value for Search Admin backend: {_raw_port}") from exc

# Bind privately to loopback; expose only through an approved reverse proxy.
bind = f"127.0.0.1:{_port}"
timeout = int(os.getenv("GUNICORN_TIMEOUT", "120"))
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info").lower()
proc_name = "bonc-search-admin-backend"
