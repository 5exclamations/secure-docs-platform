"""Screenshots of the running services (Swagger UI, Prometheus targets, Jaeger traces, Grafana).

pip install playwright && playwright install chromium
python scripts/capture_screenshots.py --env-file .env --out docs/img
"""

from __future__ import annotations

import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env-file", default=".env")
    ap.add_argument("--out", default="docs/img")
    args = ap.parse_args()
    env = dict(
        line.split("=", 1)
        for line in Path(args.env_file).read_text().splitlines()
        if "=" in line and not line.startswith("#")
    )
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto("http://localhost:8000/docs", wait_until="networkidle")
        page.wait_for_timeout(1500)
        page.screenshot(path=str(out / "compose-swagger-ui.png"))

        page.goto("http://localhost:9090/targets", wait_until="networkidle")
        page.wait_for_timeout(1500)
        page.screenshot(path=str(out / "compose-prometheus-targets.png"))

        page.goto("http://localhost:16686/search?service=secure-docs-api&limit=20", wait_until="networkidle")
        page.wait_for_timeout(3000)
        page.screenshot(path=str(out / "compose-jaeger-traces.png"))

        ctx = browser.new_context(
            viewport={"width": 1600, "height": 1200},
            http_credentials={"username": "admin", "password": env["GRAFANA_ADMIN_PASSWORD"]},
        )
        g = ctx.new_page()
        g.goto(
            "http://localhost:3000/d/secure-docs/secure-docs-api?orgId=1&from=now-30m&to=now&kiosk",
            wait_until="networkidle",
        )
        g.wait_for_timeout(6000)
        g.screenshot(path=str(out / "compose-grafana-dashboard.png"))
        browser.close()


if __name__ == "__main__":
    main()
