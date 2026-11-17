import os
import subprocess
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import Settings


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def test_health_endpoint_database_connected():
    client = TestClient(app)
    res = client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "healthy"
    assert body["database"] == "connected"


def test_health_endpoint_database_failure_returns_503_without_secrets(monkeypatch):
    class FailingSession:
        def execute(self, *_args, **_kwargs):
            raise RuntimeError("postgresql://secret_user:secret_pass@neon.tech/db connection refused")

        def close(self):
            pass

    monkeypatch.setattr("app.main.SessionLocal", lambda: FailingSession())
    client = TestClient(app)
    res = client.get("/health")
    assert res.status_code == 503
    body = res.json()
    assert body["status"] == "unhealthy"
    assert body["database"] == "unavailable"
    assert "secret_pass" not in res.text
    assert "neon.tech" not in res.text
    assert "RuntimeError" not in res.text


def test_production_settings_reject_dev_defaults_and_wildcards():
    with pytest.raises(ValueError, match="SECRET_KEY"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="cognisec_super_secret_jwt_key_2026_agentic_zero_trust_defense",
            BOOTSTRAP_ADMIN_KEY="prod-bootstrap-key-strong-123",
        )

    with pytest.raises(ValueError, match="BOOTSTRAP_ADMIN_KEY"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="prod-super-strong-jwt-secret-key-value-2026",
            BOOTSTRAP_ADMIN_KEY="cognisec_dev_bootstrap_secret_2026",
        )

    prod = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="prod-super-strong-jwt-secret-key-value-2026",
        BOOTSTRAP_ADMIN_KEY="prod-bootstrap-key-strong-123",
        EXHIBITION_DEMO_MAILBOX_OVERRIDE=True,
        CORS_ORIGINS=["*", "https://cognisec.onrender.com"],
    )
    assert prod.EXHIBITION_DEMO_MAILBOX_OVERRIDE is False
    assert prod.CORS_ORIGINS == ["https://cognisec.onrender.com"]


def test_frontend_api_url_resolution_never_falls_back_to_localhost_in_production():
    script = """
    const fs = require('fs');
    const vm = require('vm');
    const code = fs.readFileSync('cognisec-client.js', 'utf8');

    function runWith(winProps) {
      const ctx = {
        window: Object.assign({ addEventListener: () => {}, dispatchEvent: () => {} }, winProps),
        document: {
          addEventListener: () => {},
          querySelector: () => null,
          getElementById: () => null
        },
        CustomEvent: function(type, opts) { return { type, detail: opts ? opts.detail : null }; },
        localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
        sessionStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
        navigator: { userAgent: 'node-test' },
        performance: { now: () => 0 },
        console: { log: () => {}, warn: () => {}, error: () => {} },
        setTimeout, clearTimeout, setInterval, clearInterval,
        URLSearchParams
      };
      ctx.window.location = winProps.location;
      vm.runInNewContext(code, ctx);
      return ctx.window.COGNISEC_RESOLVED_API_BASE;
    }

    const localRes = runWith({ location: { hostname: '127.0.0.1', protocol: 'http:' }, COGNISEC_API_BASE: '' });
    if (localRes !== 'http://127.0.0.1:8000/api') throw new Error('localRes=' + localRes);

    const prodMissing = runWith({ location: { hostname: 'cognisec-ui.onrender.com', protocol: 'https:' }, COGNISEC_API_BASE: '' });
    if (prodMissing !== '') throw new Error('prodMissing=' + prodMissing);

    const prodConfigured = runWith({
      location: { hostname: 'cognisec-ui.onrender.com', protocol: 'https:' },
      COGNISEC_API_BASE: 'http://cognisec-api.onrender.com/'
    });
    if (prodConfigured !== 'https://cognisec-api.onrender.com/api') throw new Error('prodConfigured=' + prodConfigured);

    console.log('FRONTEND_URL_RESOLUTION_OK');
    process.exit(0);
    """
    proc = subprocess.run(
        ["node", "-e", script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "FRONTEND_URL_RESOLUTION_OK" in proc.stdout
