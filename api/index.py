"""Vercel serverless entrypoint.

Vercel's Python runtime looks for an ASGI/WSGI callable named `app` in files
under api/. The application itself lives in backend/app/, which expects
`backend/` to be the import root -- every module does `from app.config import
...`, and local dev runs uvicorn with cwd=backend (see .claude/launch.json) --
so that directory goes on sys.path before the import below.

This file deliberately contains no application logic. Anything that belongs to
the app belongs in backend/app/, so that the container/VM deployment path
(uvicorn app.main:app) and this one stay byte-for-byte equivalent.
"""
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.main import app  # noqa: E402

__all__ = ["app"]
