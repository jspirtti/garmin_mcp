"""Unit tests for the GARMIN_MCP_PATH_SECRET endpoint gate."""

import logging
import os
import secrets
from unittest.mock import patch

import pytest
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.testclient import TestClient

from garmin_mcp import _RedactFilter, _http_paths, _parse_path_secret

SECRET = secrets.token_urlsafe(32)

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1.0"},
    },
}
MCP_HEADERS = {"Accept": "application/json, text/event-stream"}


class TestParsePathSecret:
    def test_unset_returns_none(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GARMIN_MCP_PATH_SECRET", None)
            assert _parse_path_secret() is None

    def test_blank_returns_none(self):
        with patch.dict(os.environ, {"GARMIN_MCP_PATH_SECRET": "   "}):
            assert _parse_path_secret() is None

    def test_valid_secret_is_returned_stripped(self):
        with patch.dict(os.environ, {"GARMIN_MCP_PATH_SECRET": f"  {SECRET}\n"}):
            assert _parse_path_secret() == SECRET

    def test_short_secret_raises(self):
        with patch.dict(os.environ, {"GARMIN_MCP_PATH_SECRET": "a" * 31}):
            with pytest.raises(ValueError, match="at least 32"):
                _parse_path_secret()

    @pytest.mark.parametrize("bad_char", ["/", "?", "#", "%", " ", "."])
    def test_non_url_safe_secret_raises(self, bad_char):
        with patch.dict(os.environ, {"GARMIN_MCP_PATH_SECRET": "a" * 32 + bad_char + "b"}):
            with pytest.raises(ValueError, match="URL-safe"):
                _parse_path_secret()


class TestHttpPaths:
    def test_no_secret_keeps_default_paths(self):
        assert _http_paths(None) == {
            "streamable_http_path": "/mcp",
            "sse_path": "/sse",
            "message_path": "/messages/",
        }

    def test_secret_prefixes_every_path(self):
        assert _http_paths(SECRET) == {
            "streamable_http_path": f"/{SECRET}/mcp",
            "sse_path": f"/{SECRET}/sse",
            "message_path": f"/{SECRET}/messages/",
        }


class TestStreamableHttpRouting:
    @staticmethod
    def _client(secret):
        # 0.0.0.0 mirrors a container deploy (no DNS-rebinding host allowlist).
        app = FastMCP("test", host="0.0.0.0", **_http_paths(secret))
        return TestClient(app.streamable_http_app())

    def test_bare_mcp_path_is_404_when_secret_set(self):
        with self._client(SECRET) as client:
            resp = client.post("/mcp", json=INITIALIZE, headers=MCP_HEADERS)
        assert resp.status_code == 404

    def test_wrong_secret_is_404(self):
        with self._client(SECRET) as client:
            wrong = secrets.token_urlsafe(32)
            resp = client.post(f"/{wrong}/mcp", json=INITIALIZE, headers=MCP_HEADERS)
        assert resp.status_code == 404

    def test_secret_path_serves_mcp(self):
        with self._client(SECRET) as client:
            resp = client.post(f"/{SECRET}/mcp", json=INITIALIZE, headers=MCP_HEADERS)
        assert resp.status_code == 200
        assert "serverInfo" in resp.text

    def test_no_secret_serves_bare_mcp_path(self):
        with self._client(None) as client:
            resp = client.post("/mcp", json=INITIALIZE, headers=MCP_HEADERS)
        assert resp.status_code == 200


class TestRedactFilter:
    def test_masks_secret_in_access_log_args(self):
        record = logging.LogRecord(
            "uvicorn.access", logging.INFO, __file__, 0,
            '%s - "%s %s HTTP/%s" %d',
            ("1.2.3.4:5678", "POST", f"/{SECRET}/mcp", "1.1", 200),
            None,
        )
        assert _RedactFilter(SECRET).filter(record) is True
        assert SECRET not in record.getMessage()
        assert "/***/mcp" in record.getMessage()

    def test_masks_secret_in_message(self):
        record = logging.LogRecord(
            "x", logging.INFO, __file__, 0, f"path /{SECRET}/mcp", None, None
        )
        _RedactFilter(SECRET).filter(record)
        assert record.getMessage() == "path /***/mcp"

    def test_filter_survives_uvicorn_logging_config(self):
        # main() adds the filter before FastMCP builds uvicorn.Config, which
        # re-applies uvicorn's dictConfig; the filter must still be attached.
        logger = logging.getLogger("uvicorn.access")
        redact = _RedactFilter(SECRET)
        logger.addFilter(redact)
        try:
            uvicorn.Config(lambda scope, receive, send: None)
            assert redact in logger.filters
        finally:
            logger.removeFilter(redact)
