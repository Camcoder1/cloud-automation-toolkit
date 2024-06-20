#!/usr/bin/env python3
"""Cloud Resource Tag Compliance Scanner

Scans cloud resources (AWS, GCP) for missing required tags/labels and
reports compliance status. Optionally auto-applies default values for
missing tags to bring resources into compliance.

Environment Variables:
    AWS_PROFILE          - AWS CLI named profile
    GCP_PROJECT          - GCP project ID
    GOOGLE_APPLICATION_CREDENTIALS - Path to GCP service account key

Usage:
    python resource_tagger.py --provider aws --region us-east-1
    python resource_tagger.py --provider gcp --project my-project --auto-apply
    python resource_tagger.py --provider aws --region us-east-1 --output report.json
"""

from __future__ import annotations

import abc
import argparse
import json
import logging
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class TagViolation:
    """A single tag compliance violation."""

    resource_id: str
    resource_type: str
    region: str
    missing_tags: list[str]
    existing_tags: dict[str, str]


@dataclass
class RemediationAction:
    """Record of an auto-applied tag remediation."""

    resource_id: str
    resource_type: str
    tags_applied: dict[str, str]
    status: str  # "success" | "failed"
    error: str = ""


@dataclass
class ComplianceReport:
    """Full compliance scan report."""

    generated_at: str
    provider: str
    total_resources_scanned: int
    compliant: int
    non_compliant: int
    compliance_rate: float
    required_tags: list[str]
    violations: list[TagViolation]
    remediations: list[RemediationAction] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

@dataclass
class TagPolicy:
    """Defines required tags and default fallback values."""

    required_tags: list[str]
    default_values: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> TagPolicy:
        """Build a policy from the tagging section of a YAML config."""
        tagging = config.get("tagging", {})
        return cls(
            required_tags=tagging.get("required_tags", []),
            default_values=tagging.get("default_values", {}),
        )

    @classmethod
    def default(cls) -> TagPolicy:
        """Sensible default policy when no config is provided."""
        return cls(
            required_tags=["environment", "owner", "cost-center"],
            default_values={
                "environment": "unknown",
                "owner": "unassigned",
                "cost-center": "unassigned",
            },
        )


# ---------------------------------------------------------------------------
# Provider interface
# ---------------------------------------------------------------------------

@dataclass
class CloudResource:
    """Normalized cloud resource with its current tags."""

    resource_id: str
    resource_type: str
    region: str
    tags: dict[str, str]


class TaggingProvider(abc.ABC):
    """Abstract interface for scanning and applying tags."""

    @abc.abstractmethod
    def scan_resources(self) -> list[CloudResource]:
        """Return all taggable resources from the provider."""
        ...

    @abc.abstractmethod
    def apply_tags(self, resource_id: str, tags: dict[str, str]) -> None:
        """Apply tags to a specific resource."""
        ...


# ---------------------------------------------------------------------------
# AWS provider
# ---------------------------------------------------------------------------

class AWSTaggingProvider(TaggingProvider):
    """Scans and tags AWS resources via the Resource Groups Tagging API."""

    def __init__(
        self,
        region: str = "us-east-1",
        profile: str | None = None,
        resource_types: list[str] | None = None,
    ) -> None:
        self.region = region
        self.profile = profile
        self.resource_types = resource_types or []

    def scan_resources(self) -> list[CloudResource]:
        try:
            import boto3  # type: ignore[import-untyped]
        except ImportError:
            logger.error("boto3 is not installed. Install with: pip install boto3")
            raise

        session = (
            boto3.Session(profile_name=self.profile, region_name=self.region)
            if self.profile
            else boto3.Session(region_name=self.region)
        )
        client = session.client("resourcegroupstaggingapi")

        resources: list[CloudResource] = []
        paginator = client.get_paginator("get_resources")

        kwargs: dict[str, Any] = {}
        if self.resource_types:
            kwargs["ResourceTypeFilters"] = self.resource_types

        for page in paginator.paginate(**kwargs):
            for item in page.get("ResourceTagMappingList", []):
                arn = item["ResourceARN"]
                tags = {t["Key"]: t["Value"] for t in item.get("Tags", [])}

                # Extract type from ARN: arn:aws:service:region:account:type/id
                parts = arn.split(":")
                resource_type = parts[2] if len(parts) > 2 else "unknown"

                resources.append(
                    CloudResource(
                        resource_id=arn,
                        resource_type=resource_type,
                        region=self.region,
                        tags=tags,
                    )
                )

        logger.info("AWS %s: scanned %d resources", self.region, len(resources))
        return resources

    def apply_tags(self, resource_id: str, tags: dict[str, str]) -> None:
        import boto3  # type: ignore[import-untyped]

        session = (
            boto3.Session(profile_name=self.profile, region_name=self.region)
            if self.profile
            else boto3.Session(region_name=self.region)
        )
        client = session.client("resourcegroupstaggingapi")
        client.tag_resources(
            ResourceARNList=[resource_id],
            Tags=tags,
        )


# ---------------------------------------------------------------------------
# GCP provider
# ---------------------------------------------------------------------------

class GCPTaggingProvider(TaggingProvider):
    """Scans and labels GCP Compute Engine instances."""

    def __init__(self, project: str) -> None:
        self.project = project

    def scan_resources(self) -> list[CloudResource]:
        try:
            from google.cloud import compute_v1  # type: ignore[import-untyped]
        except ImportError:
            logger.error(
                "google-cloud-compute not installed. "
                "Install with: pip install google-cloud-compute"
            )
            raise

        client = compute_v1.InstancesClient()
        resources: list[CloudResource] = []

        request = compute_v1.AggregatedListInstancesRequest(project=self.project)
        for zone_key, scoped_list in client.aggregated_list(request=request):
            if not scoped_list.instances:
                continue

            zone_name = zone_key.split("/")[-1] if "/" in zone_key else zone_key
            region = "-".join(zone_name.split("-")[:-1])

            for instance in scoped_list.instances:
                labels = dict(instance.labels) if instance.labels else {}
                resources.append(
                    CloudResource(
                        resource_id=f"projects/{self.project}/zones/{zone_name}/instances/{instance.name}",
                        resource_type="compute.instances",
                        region=region,
                        tags=labels,
                    )
                )

        logger.info("GCP %s: scanned %d resources", self.project, len(resources))
        return resources

    def apply_tags(self, resource_id: str, tags: dict[str, str]) -> None:
        from google.cloud import compute_v1  # type: ignore[import-untyped]

        # Parse resource_id: projects/{project}/zones/{zone}/instances/{name}
        parts = resource_id.split("/")
        project = parts[1]
        zone = parts[3]
        instance_name = parts[5]

        client = compute_v1.InstancesClient()
        instance = client.get(project=project, zone=zone, instance=instance_name)

        current_labels = dict(instance.labels) if instance.labels else {}
        current_labels.update(tags)

        labels_body = compute_v1.InstancesSetLabelsRequest(
            label_fingerprint=instance.label_fingerprint,
            labels=current_labels,
        )
        client.set_labels(
            project=project,
            zone=zone,
            instance=instance_name,
            instances_set_labels_request_resource=labels_body,
        )


# ---------------------------------------------------------------------------
# Compliance engine
# ---------------------------------------------------------------------------

def scan_compliance(
    provider: TaggingProvider,
    policy: TagPolicy,
) -> tuple[list[CloudResource], list[TagViolation]]:
    """Scan resources and identify tag violations.

    Returns:
        Tuple of (all_resources, violations).
    """
    resources = provider.scan_resources()
    violations: list[TagViolation] = []

    for resource in resources:
        missing = [
            tag for tag in policy.required_tags if tag not in resource.tags
        ]
        if missing:
            violations.append(
                TagViolation(
                    resource_id=resource.resource_id,
                    resource_type=resource.resource_type,
                    region=resource.region,
                    missing_tags=missing,
                    existing_tags=resource.tags,
                )
            )

    return resources, violations


def remediate_violations(
    provider: TaggingProvider,
    violations: list[TagViolation],
    policy: TagPolicy,
) -> list[RemediationAction]:
    """Apply default tag values to non-compliant resources.

    Only applies tags that have a default value defined in the policy.
    """
    actions: list[RemediationAction] = []

    for violation in violations:
        tags_to_apply: dict[str, str] = {}
        for tag in violation.missing_tags:
            if tag in policy.default_values:
                tags_to_apply[tag] = policy.default_values[tag]

        if not tags_to_apply:
            continue

        try:
            provider.apply_tags(violation.resource_id, tags_to_apply)
            actions.append(
                RemediationAction(
                    resource_id=violation.resource_id,
                    resource_type=violation.resource_type,
                    tags_applied=tags_to_apply,
                    status="success",
                )
            )
            logger.info(
                "Applied tags to %s: %s",
                violation.resource_id,
                tags_to_apply,
            )
        except Exception as exc:
            actions.append(
                RemediationAction(
                    resource_id=violation.resource_id,
                    resource_type=violation.resource_type,
                    tags_applied=tags_to_apply,
                    status="failed",
                    error=str(exc),
                )
            )
            logger.warning(
                "Failed to apply tags to %s: %s",
                violation.resource_id,
                exc,
            )

    return actions


def build_report(
    provider_name: str,
    policy: TagPolicy,
    resources: list[CloudResource],
    violations: list[TagViolation],
    remediations: list[RemediationAction] | None = None,
) -> ComplianceReport:
    """Build the compliance report."""
    total = len(resources)
    non_compliant = len(violations)
    compliant = total - non_compliant
    rate = (compliant / total * 100) if total > 0 else 100.0

    return ComplianceReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        provider=provider_name,
        total_resources_scanned=total,
        compliant=compliant,
        non_compliant=non_compliant,
        compliance_rate=round(rate, 1),
        required_tags=policy.required_tags,
        violations=violations,
        remediations=remediations or [],
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan cloud resources for tag/label compliance.",
    )
    parser.add_argument(
        "--provider",
        choices=["aws", "gcp"],
        required=True,
        help="Cloud provider to scan",
    )
    parser.add_argument(
        "--project",
        default=os.getenv("GCP_PROJECT", ""),
        help="GCP project ID (GCP only)",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (AWS only, default: us-east-1)",
    )
    parser.add_argument(
        "--aws-profile",
        default=os.getenv("AWS_PROFILE"),
        help="AWS CLI profile name",
    )
    parser.add_argument(
        "--required-tags",
        default=None,
        help="Comma-separated list of required tags (overrides defaults)",
    )
    parser.add_argument(
        "--auto-apply",
        action="store_true",
        help="Auto-apply default values for missing tags",
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

    # Build policy
    policy = TagPolicy.default()
    if args.required_tags:
        policy.required_tags = [t.strip() for t in args.required_tags.split(",")]

    # Build provider
    provider: TaggingProvider
    if args.provider == "aws":
        provider = AWSTaggingProvider(
            region=args.region,
            profile=args.aws_profile,
        )
    elif args.provider == "gcp":
        if not args.project:
            logger.error("GCP project is required. Set --project or GCP_PROJECT.")
            return 1
        provider = GCPTaggingProvider(project=args.project)
    else:
        logger.error("Unknown provider: %s", args.provider)
        return 1

    try:
        resources, violations = scan_compliance(provider, policy)
    except Exception:
        logger.exception("Compliance scan failed.")
        return 1

    remediations: list[RemediationAction] = []
    if args.auto_apply and violations:
        logger.info("Auto-applying default tags to %d non-compliant resources...", len(violations))
        remediations = remediate_violations(provider, violations, policy)

    report = build_report(
        provider_name=args.provider,
        policy=policy,
        resources=resources,
        violations=violations,
        remediations=remediations,
    )

    report_json = json.dumps(asdict(report), indent=2, default=str)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report_json)
        logger.info("Report written to %s", args.output)
    else:
        print(report_json)

    logger.info(
        "Compliance: %.1f%% (%d/%d compliant) | %d violations | %d remediations",
        report.compliance_rate,
        report.compliant,
        report.total_resources_scanned,
        report.non_compliant,
        len(remediations),
    )

    if report.non_compliant > 0:
        return 2  # signal non-compliance to monitoring
    return 0


if __name__ == "__main__":
    sys.exit(main())
