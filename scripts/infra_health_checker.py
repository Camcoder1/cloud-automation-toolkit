#!/usr/bin/env python3
"""Infrastructure Health Checker

Performs parallel health checks against DNS, HTTP endpoints, and SSL
certificates. Reads targets from a YAML config file and outputs structured
JSON results suitable for monitoring system integration.

Exit Codes:
    0 - All checks passed
    1 - Configuration or runtime error
    2 - One or more checks failed

Usage:
    python infra_health_checker.py --config config.yaml
    python infra_health_checker.py --config config.yaml --output results.json
    python infra_health_checker.py --config config.yaml --checks dns,ssl
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import requests
import yaml

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10
DEFAULT_SSL_WARN_DAYS = 30
MAX_WORKERS = 20


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    """Result of a single health check."""

    check_type: str
    target: str
    status: str  # "pass" | "fail" | "warn"
    message: str
    latency_ms: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class HealthReport:
    """Aggregated health check report."""

    generated_at: str
    total_checks: int
    passed: int
    failed: int
    warnings: int
    results: list[CheckResult]


# ---------------------------------------------------------------------------
# Check implementations
# ---------------------------------------------------------------------------

def check_dns(
    hostname: str,
    expected_ip: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> CheckResult:
    """Resolve a hostname and optionally verify the resulting IP."""
    target = hostname
    start = _now_ms()
    try:
        socket.setdefaulttimeout(timeout)
        result = socket.getaddrinfo(hostname, None)
        resolved_ips = sorted({addr[4][0] for addr in result})
        latency = _now_ms() - start

        if expected_ip and expected_ip not in resolved_ips:
            return CheckResult(
                check_type="dns",
                target=target,
                status="fail",
                message=f"Expected {expected_ip}, got {resolved_ips}",
                latency_ms=latency,
                details={"resolved_ips": resolved_ips, "expected_ip": expected_ip},
            )

        return CheckResult(
            check_type="dns",
            target=target,
            status="pass",
            message=f"Resolved to {resolved_ips}",
            latency_ms=latency,
            details={"resolved_ips": resolved_ips},
        )
    except socket.gaierror as exc:
        return CheckResult(
            check_type="dns",
            target=target,
            status="fail",
            message=f"DNS resolution failed: {exc}",
            latency_ms=_now_ms() - start,
        )


def check_http(
    url: str,
    expected_status: int = 200,
    timeout: float = DEFAULT_TIMEOUT,
) -> CheckResult:
    """Send an HTTP GET and validate the response status code."""
    target = url
    start = _now_ms()
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        latency = _now_ms() - start

        if resp.status_code != expected_status:
            return CheckResult(
                check_type="http",
                target=target,
                status="fail",
                message=f"Expected {expected_status}, got {resp.status_code}",
                latency_ms=latency,
                details={
                    "status_code": resp.status_code,
                    "expected_status": expected_status,
                },
            )

        return CheckResult(
            check_type="http",
            target=target,
            status="pass",
            message=f"HTTP {resp.status_code} OK",
            latency_ms=latency,
            details={"status_code": resp.status_code},
        )
    except requests.RequestException as exc:
        return CheckResult(
            check_type="http",
            target=target,
            status="fail",
            message=f"HTTP request failed: {exc}",
            latency_ms=_now_ms() - start,
        )


def check_ssl(
    hostname: str,
    port: int = 443,
    warn_days: int = DEFAULT_SSL_WARN_DAYS,
    timeout: float = DEFAULT_TIMEOUT,
) -> CheckResult:
    """Connect via TLS and check certificate expiry."""
    target = f"{hostname}:{port}"
    start = _now_ms()
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()

        latency = _now_ms() - start

        if not cert:
            return CheckResult(
                check_type="ssl",
                target=target,
                status="fail",
                message="No certificate returned",
                latency_ms=latency,
            )

        not_after_str = cert.get("notAfter", "")
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        not_after = not_after.replace(tzinfo=timezone.utc)
        days_remaining = (not_after - datetime.now(timezone.utc)).days

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))

        details = {
            "subject_cn": subject.get("commonName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "not_after": not_after.isoformat(),
            "days_remaining": days_remaining,
        }

        if days_remaining < 0:
            return CheckResult(
                check_type="ssl",
                target=target,
                status="fail",
                message=f"Certificate expired {abs(days_remaining)} days ago",
                latency_ms=latency,
                details=details,
            )

        if days_remaining < warn_days:
            return CheckResult(
                check_type="ssl",
                target=target,
                status="warn",
                message=f"Certificate expires in {days_remaining} days",
                latency_ms=latency,
                details=details,
            )

        return CheckResult(
            check_type="ssl",
            target=target,
            status="pass",
            message=f"Certificate valid for {days_remaining} days",
            latency_ms=latency,
            details=details,
        )
    except Exception as exc:
        return CheckResult(
            check_type="ssl",
            target=target,
            status="fail",
            message=f"SSL check failed: {exc}",
            latency_ms=_now_ms() - start,
        )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict[str, Any]:
    """Load health check targets from a YAML config file."""
    with open(path, "r", encoding="utf-8") as fh:
        config = yaml.safe_load(fh)
    return config.get("health_checks", {})


def run_checks(
    config: dict[str, Any],
    check_types: set[str] | None = None,
    max_workers: int = MAX_WORKERS,
) -> list[CheckResult]:
    """Execute all configured checks in parallel.

    Args:
        config: The health_checks section of the YAML config.
        check_types: Subset of check types to run (None = all).
        max_workers: Thread pool size for parallel execution.

    Returns:
        A list of CheckResult instances.
    """
    futures = []
    results: list[CheckResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # DNS checks
        if check_types is None or "dns" in check_types:
            for entry in config.get("dns", []):
                futures.append(
                    executor.submit(
                        check_dns,
                        hostname=entry["hostname"],
                        expected_ip=entry.get("expected_ip"),
                    )
                )

        # HTTP checks
        if check_types is None or "http" in check_types:
            for entry in config.get("http", []):
                futures.append(
                    executor.submit(
                        check_http,
                        url=entry["url"],
                        expected_status=entry.get("expected_status", 200),
                        timeout=entry.get("timeout_seconds", DEFAULT_TIMEOUT),
                    )
                )

        # SSL checks
        if check_types is None or "ssl" in check_types:
            for entry in config.get("ssl", []):
                futures.append(
                    executor.submit(
                        check_ssl,
                        hostname=entry["hostname"],
                        port=entry.get("port", 443),
                        warn_days=entry.get("warn_days", DEFAULT_SSL_WARN_DAYS),
                    )
                )

        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                logger.error("Check raised an unhandled exception: %s", exc)
                results.append(
                    CheckResult(
                        check_type="unknown",
                        target="unknown",
                        status="fail",
                        message=f"Unhandled exception: {exc}",
                    )
                )

    return results


def build_report(results: list[CheckResult]) -> HealthReport:
    """Build a summary report from individual check results."""
    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status == "fail")
    warnings = sum(1 for r in results if r.status == "warn")

    return HealthReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        total_checks=len(results),
        passed=passed,
        failed=failed,
        warnings=warnings,
        results=results,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_ms() -> float:
    """Current time in milliseconds (monotonic-ish via UTC)."""
    import time
    return time.monotonic() * 1000


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run infrastructure health checks from a YAML config.",
    )
    parser.add_argument(
        "--config", "-c",
        required=True,
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output JSON file path (default: stdout)",
    )
    parser.add_argument(
        "--checks",
        default=None,
        help="Comma-separated check types to run: dns,http,ssl (default: all)",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=MAX_WORKERS,
        help=f"Max parallel workers (default: {MAX_WORKERS})",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )

    try:
        config = load_config(args.config)
    except FileNotFoundError:
        logger.error("Config file not found: %s", args.config)
        return 1
    except yaml.YAMLError as exc:
        logger.error("Failed to parse YAML config: %s", exc)
        return 1

    check_types: set[str] | None = None
    if args.checks:
        check_types = {c.strip().lower() for c in args.checks.split(",")}
        valid = {"dns", "http", "ssl"}
        invalid = check_types - valid
        if invalid:
            logger.error("Unknown check types: %s (valid: %s)", invalid, valid)
            return 1

    results = run_checks(config, check_types=check_types, max_workers=args.workers)
    report = build_report(results)

    report_json = json.dumps(asdict(report), indent=2, default=str)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report_json)
        logger.info("Report written to %s", args.output)
    else:
        print(report_json)

    logger.info(
        "Health check complete: %d passed, %d failed, %d warnings",
        report.passed,
        report.failed,
        report.warnings,
    )

    if report.failed > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
