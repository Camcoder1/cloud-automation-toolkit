#!/usr/bin/env python3
"""GCP Cost Analyzer

Queries a BigQuery billing export table to identify top cost drivers,
project-level spend, and cost anomalies over a configurable time window.

Prerequisites:
    - BigQuery billing export enabled in your GCP organization
    - Application Default Credentials configured:
        gcloud auth application-default login
    - Or set GOOGLE_APPLICATION_CREDENTIALS to a service account key

Usage:
    python gcp_cost_analyzer.py --project my-billing-project --days 30
    python gcp_cost_analyzer.py --project my-billing-project --days 7 --threshold 20
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CostEntry:
    """A single aggregated cost line item."""

    project_id: str
    service_description: str
    sku_description: str
    total_cost: float
    currency: str
    usage_start: str
    usage_end: str


@dataclass
class CostAnomaly:
    """A detected cost anomaly for a project-service pair."""

    project_id: str
    service_description: str
    current_period_cost: float
    previous_period_cost: float
    change_percent: float
    severity: str  # "warning" | "critical"


@dataclass
class CostReport:
    """Complete cost analysis report."""

    generated_at: str
    period_days: int
    total_spend: float
    currency: str
    top_projects: list[dict[str, float]]
    top_services: list[dict[str, float]]
    top_skus: list[CostEntry]
    anomalies: list[CostAnomaly]


# ---------------------------------------------------------------------------
# BigQuery billing client
# ---------------------------------------------------------------------------

class BillingQueryClient:
    """Wraps BigQuery access for billing export analysis."""

    def __init__(
        self,
        billing_project: str,
        dataset: str = "billing_export",
        table: str = "gcp_billing_export_v1",
    ) -> None:
        self.billing_project = billing_project
        self.dataset = dataset
        self.table = table
        self._client: object | None = None

    @property
    def full_table_id(self) -> str:
        return f"{self.billing_project}.{self.dataset}.{self.table}"

    def _get_client(self) -> object:
        """Lazy-initialize the BigQuery client."""
        if self._client is None:
            try:
                from google.cloud import bigquery  # type: ignore[import-untyped]
            except ImportError:
                logger.error(
                    "google-cloud-bigquery is not installed. "
                    "Install with: pip install google-cloud-bigquery"
                )
                raise
            self._client = bigquery.Client(project=self.billing_project)
        return self._client

    def query_costs_by_project(self, days: int) -> list[dict]:
        """Return total cost grouped by project for the given period."""
        query = f"""
            SELECT
                project.id AS project_id,
                SUM(cost) AS total_cost,
                currency
            FROM `{self.full_table_id}`
            WHERE usage_start_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
            GROUP BY project_id, currency
            ORDER BY total_cost DESC
        """
        return self._execute_query(query)

    def query_costs_by_service(self, days: int) -> list[dict]:
        """Return total cost grouped by service for the given period."""
        query = f"""
            SELECT
                service.description AS service_description,
                SUM(cost) AS total_cost,
                currency
            FROM `{self.full_table_id}`
            WHERE usage_start_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
            GROUP BY service_description, currency
            ORDER BY total_cost DESC
        """
        return self._execute_query(query)

    def query_top_skus(self, days: int, limit: int = 20) -> list[dict]:
        """Return the most expensive SKUs in the period."""
        query = f"""
            SELECT
                project.id AS project_id,
                service.description AS service_description,
                sku.description AS sku_description,
                SUM(cost) AS total_cost,
                currency,
                MIN(usage_start_time) AS usage_start,
                MAX(usage_end_time) AS usage_end
            FROM `{self.full_table_id}`
            WHERE usage_start_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
            GROUP BY project_id, service_description, sku_description, currency
            ORDER BY total_cost DESC
            LIMIT {limit}
        """
        return self._execute_query(query)

    def query_period_comparison(
        self, current_days: int
    ) -> list[dict]:
        """Compare per-project-service costs between two adjacent periods."""
        query = f"""
            WITH current_period AS (
                SELECT
                    project.id AS project_id,
                    service.description AS service_description,
                    SUM(cost) AS total_cost
                FROM `{self.full_table_id}`
                WHERE usage_start_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {current_days} DAY)
                GROUP BY project_id, service_description
            ),
            previous_period AS (
                SELECT
                    project.id AS project_id,
                    service.description AS service_description,
                    SUM(cost) AS total_cost
                FROM `{self.full_table_id}`
                WHERE usage_start_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {current_days * 2} DAY)
                  AND usage_start_time < TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {current_days} DAY)
                GROUP BY project_id, service_description
            )
            SELECT
                COALESCE(c.project_id, p.project_id) AS project_id,
                COALESCE(c.service_description, p.service_description) AS service_description,
                IFNULL(c.total_cost, 0) AS current_cost,
                IFNULL(p.total_cost, 0) AS previous_cost
            FROM current_period c
            FULL OUTER JOIN previous_period p
                ON c.project_id = p.project_id
                AND c.service_description = p.service_description
            ORDER BY current_cost DESC
        """
        return self._execute_query(query)

    def _execute_query(self, query: str) -> list[dict]:
        """Execute a BigQuery SQL query and return rows as dicts."""
        client = self._get_client()
        logger.debug("Executing query:\n%s", query)
        job = client.query(query)  # type: ignore[union-attr]
        results = job.result()
        rows = [dict(row) for row in results]
        logger.info("Query returned %d rows.", len(rows))
        return rows


# ---------------------------------------------------------------------------
# Analysis logic
# ---------------------------------------------------------------------------

def detect_anomalies(
    comparison_rows: list[dict],
    threshold_percent: float = 20.0,
) -> list[CostAnomaly]:
    """Flag project-service pairs whose cost changed beyond the threshold.

    Args:
        comparison_rows: Output from query_period_comparison.
        threshold_percent: Minimum % change to flag as anomaly.

    Returns:
        A list of CostAnomaly entries sorted by severity.
    """
    anomalies: list[CostAnomaly] = []

    for row in comparison_rows:
        current = float(row.get("current_cost", 0))
        previous = float(row.get("previous_cost", 0))

        if previous == 0:
            if current > 10:  # new spend over $10 is worth noting
                change_pct = 100.0
            else:
                continue
        else:
            change_pct = ((current - previous) / previous) * 100

        if abs(change_pct) < threshold_percent:
            continue

        severity = "critical" if abs(change_pct) >= 50 else "warning"

        anomalies.append(
            CostAnomaly(
                project_id=row.get("project_id", "unknown"),
                service_description=row.get("service_description", "unknown"),
                current_period_cost=round(current, 2),
                previous_period_cost=round(previous, 2),
                change_percent=round(change_pct, 1),
                severity=severity,
            )
        )

    anomalies.sort(key=lambda a: abs(a.change_percent), reverse=True)
    return anomalies


def build_report(
    days: int,
    project_rows: list[dict],
    service_rows: list[dict],
    sku_rows: list[dict],
    anomalies: list[CostAnomaly],
) -> CostReport:
    """Assemble all analysis results into a single report."""
    total_spend = sum(float(r.get("total_cost", 0)) for r in project_rows)
    currency = project_rows[0].get("currency", "USD") if project_rows else "USD"

    top_projects = [
        {r["project_id"]: round(float(r["total_cost"]), 2)}
        for r in project_rows[:10]
    ]

    top_services = [
        {r["service_description"]: round(float(r["total_cost"]), 2)}
        for r in service_rows[:10]
    ]

    top_skus = [
        CostEntry(
            project_id=r.get("project_id", ""),
            service_description=r.get("service_description", ""),
            sku_description=r.get("sku_description", ""),
            total_cost=round(float(r.get("total_cost", 0)), 2),
            currency=r.get("currency", "USD"),
            usage_start=str(r.get("usage_start", "")),
            usage_end=str(r.get("usage_end", "")),
        )
        for r in sku_rows[:20]
    ]

    return CostReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        period_days=days,
        total_spend=round(total_spend, 2),
        currency=currency,
        top_projects=top_projects,
        top_services=top_services,
        top_skus=top_skus,
        anomalies=anomalies,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze GCP billing data from BigQuery export.",
    )
    parser.add_argument(
        "--project", "-p",
        default=os.getenv("GCP_BILLING_PROJECT", ""),
        help="GCP project containing the billing export dataset",
    )
    parser.add_argument(
        "--dataset",
        default=os.getenv("GCP_BILLING_DATASET", "billing_export"),
        help="BigQuery dataset name (default: billing_export)",
    )
    parser.add_argument(
        "--table",
        default=os.getenv("GCP_BILLING_TABLE", "gcp_billing_export_v1"),
        help="BigQuery table name (default: gcp_billing_export_v1)",
    )
    parser.add_argument(
        "--days", "-d",
        type=int,
        default=30,
        help="Analysis period in days (default: 30)",
    )
    parser.add_argument(
        "--threshold", "-t",
        type=float,
        default=20.0,
        help="Anomaly detection threshold as %% change (default: 20)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output JSON file path (default: stdout)",
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

    if not args.project:
        logger.error("GCP project is required. Set --project or GCP_BILLING_PROJECT.")
        return 1

    client = BillingQueryClient(
        billing_project=args.project,
        dataset=args.dataset,
        table=args.table,
    )

    try:
        logger.info(
            "Analyzing %d days of billing data in %s",
            args.days,
            client.full_table_id,
        )

        project_rows = client.query_costs_by_project(args.days)
        service_rows = client.query_costs_by_service(args.days)
        sku_rows = client.query_top_skus(args.days)
        comparison_rows = client.query_period_comparison(args.days)

        anomalies = detect_anomalies(comparison_rows, args.threshold)

        report = build_report(
            days=args.days,
            project_rows=project_rows,
            service_rows=service_rows,
            sku_rows=sku_rows,
            anomalies=anomalies,
        )
    except Exception:
        logger.exception("Cost analysis failed.")
        return 1

    report_dict = asdict(report)
    report_json = json.dumps(report_dict, indent=2, default=str)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report_json)
        logger.info("Report written to %s", args.output)
    else:
        print(report_json)

    # Summary to stderr for pipeline use
    critical_count = sum(1 for a in anomalies if a.severity == "critical")
    warning_count = sum(1 for a in anomalies if a.severity == "warning")
    logger.info(
        "Total spend: $%.2f | Anomalies: %d critical, %d warning",
        report.total_spend,
        critical_count,
        warning_count,
    )

    if critical_count > 0:
        return 2  # non-zero to alert monitoring
    return 0


if __name__ == "__main__":
    sys.exit(main())
