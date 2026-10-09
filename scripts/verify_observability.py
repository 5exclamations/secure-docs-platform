"""Checks, against a running compose stack, that telemetry actually flows end to end:

* Prometheus scrapes the API target and has application metrics
* Jaeger received traces for the API service, and none of them contain a share-link token
* Grafana loads the provisioned dashboard and a panel query returns real samples

    python scripts/verify_observability.py --env-file .env
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path

import httpx


def load_env(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in Path(path).read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def wait_for(fn, what: str, timeout: int = 120):  # type: ignore[no-untyped-def]
    end = time.time() + timeout
    last: object = None
    while time.time() < end:
        try:
            last = fn()
            if last:
                return last
        except Exception as exc:
            last = exc
        time.sleep(3)
    raise SystemExit(f"FAIL: timed out waiting for {what} (last: {last!r})")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env-file", default=".env")
    ap.add_argument("--prometheus", default="http://localhost:9090")
    ap.add_argument("--jaeger", default="http://localhost:16686")
    ap.add_argument("--grafana", default="http://localhost:3000")
    args = ap.parse_args()
    env = load_env(args.env_file)
    results: list[tuple[str, bool]] = []

    def check(name: str, ok: bool) -> None:
        results.append((name, ok))
        print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")

    with httpx.Client(timeout=15) as c:
        print("== Prometheus")
        targets = wait_for(
            lambda: [
                t
                for t in c.get(f"{args.prometheus}/api/v1/targets").json()["data"]["activeTargets"]
                if t["labels"]["job"] == "secure-docs-api" and t["health"] == "up"
            ],
            "the API scrape target to be up",
        )
        check("API scrape target is up (bearer-token authenticated)", bool(targets))
        series = wait_for(
            lambda: c.get(f"{args.prometheus}/api/v1/query", params={"query": "sum(http_requests_total)"}).json()[
                "data"
            ]["result"],
            "http_requests_total samples",
        )
        total = float(series[0]["value"][1])
        check(f"http_requests_total has samples (sum={total:.0f})", total > 0)
        auth = c.get(f"{args.prometheus}/api/v1/query", params={"query": 'auth_events_total{event="login"}'}).json()[
            "data"
        ]["result"]
        check("auth_events_total{event=login} is recorded", bool(auth))
        rules = c.get(f"{args.prometheus}/api/v1/rules").json()["data"]["groups"]
        check("alert rules are loaded", sum(len(g["rules"]) for g in rules) >= 5)

        print("== Jaeger")
        services = wait_for(lambda: c.get(f"{args.jaeger}/api/services").json().get("data") or [], "services in Jaeger")
        check(f"service 'secure-docs-api' is present (services: {services})", "secure-docs-api" in services)
        traces = wait_for(
            lambda: (
                c.get(f"{args.jaeger}/api/traces", params={"service": "secure-docs-api", "limit": 50})
                .json()
                .get("data")
            ),
            "traces for the API",
        )
        check(f"{len(traces)} traces received", len(traces) > 0)
        blob = str(traces)
        check("traces include database spans", "db.statement" in blob or "db.system" in blob)
        leaked = re.findall(r"/shared/(?!\{token\})[^/'\"\s]+", blob)
        check("no share-link token appears in any trace", not leaked)

        print("== Grafana")
        gauth = ("admin", env["GRAFANA_ADMIN_PASSWORD"])
        health = c.get(f"{args.grafana}/api/health").json()
        check("Grafana is healthy", health.get("database") == "ok")
        found = c.get(f"{args.grafana}/api/search", params={"query": "Secure Docs"}, auth=gauth).json()
        check("dashboard 'Secure Docs API' is provisioned", any(d.get("uid") == "secure-docs" for d in found))
        dash = c.get(f"{args.grafana}/api/dashboards/uid/secure-docs", auth=gauth).json()["dashboard"]
        check(f"dashboard has {len(dash['panels'])} panels", len(dash["panels"]) >= 7)
        now = int(time.time() * 1000)
        body = {
            "from": str(now - 3_600_000),
            "to": str(now),
            "queries": [
                {
                    "refId": "A",
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "expr": dash["panels"][0]["targets"][0]["expr"],
                    "instant": False,
                    "range": True,
                    "intervalMs": 15000,
                    "maxDataPoints": 200,
                }
            ],
        }

        def panel_has_data() -> bool:
            r = c.post(f"{args.grafana}/api/ds/query", json=body, auth=gauth).json()
            frames = r["results"]["A"].get("frames", [])
            return any(f["data"]["values"] and len(f["data"]["values"][0]) > 0 for f in frames)

        check(
            "first panel query through Grafana returns real samples",
            bool(wait_for(panel_has_data, "Grafana panel data")),
        )

    failed = [n for n, ok in results if not ok]
    print("\nALL OBSERVABILITY CHECKS PASSED" if not failed else f"\n{len(failed)} CHECK(S) FAILED: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
