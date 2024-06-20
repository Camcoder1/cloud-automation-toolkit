#!/usr/bin/env python3
"""Dynamic Ansible Inventory Generator

Queries cloud provider APIs (GCP Compute Engine, AWS EC2) and emits
Ansible-compatible JSON inventory. Hosts are grouped by tags/labels,
region, and environment.

Usage as dynamic inventory script:
    ansible-playbook -i ansible_inventory_generator.py site.yml

Standalone:
    python ansible_inventory_generator.py --provider gcp --project my-project
    python ansible_inventory_generator.py --provider aws --region us-east-1
    python ansible_inventory_generator.py --list
"""

from __future__ import annotations

import abc
import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class HostEntry:
    """Normalized representation of a compute instance."""

    hostname: str
    ansible_host: str  # IP or FQDN for SSH
    provider: str
    region: str
    zone: str
    instance_id: str
    instance_type: str
    state: str
    tags: dict[str, str] = field(default_factory=dict)
    host_vars: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Provider plugin interface
# ---------------------------------------------------------------------------

class InventoryProvider(abc.ABC):
    """Abstract base class for cloud inventory providers."""

    @abc.abstractmethod
    def list_instances(self) -> list[HostEntry]:
        """Return all running instances from the provider."""
        ...

    @abc.abstractmethod
    def provider_name(self) -> str:
        """Short name for the provider (gcp, aws)."""
        ...


# ---------------------------------------------------------------------------
# GCP provider
# ---------------------------------------------------------------------------

class GCPInventoryProvider(InventoryProvider):
    """Fetches Compute Engine instances from a GCP project."""

    def __init__(self, project: str, zones: list[str] | None = None) -> None:
        self.project = project
        self.zones = zones

    def provider_name(self) -> str:
        return "gcp"

    def list_instances(self) -> list[HostEntry]:
        try:
            from google.cloud import compute_v1  # type: ignore[import-untyped]
        except ImportError:
            logger.error(
                "google-cloud-compute is not installed. "
                "Install with: pip install google-cloud-compute"
            )
            raise

        client = compute_v1.InstancesClient()
        entries: list[HostEntry] = []

        request = compute_v1.AggregatedListInstancesRequest(project=self.project)
        for zone_key, instances_scoped_list in client.aggregated_list(request=request):
            if not instances_scoped_list.instances:
                continue

            zone_name = zone_key.split("/")[-1] if "/" in zone_key else zone_key
            region = "-".join(zone_name.split("-")[:-1])

            if self.zones and zone_name not in self.zones:
                continue

            for instance in instances_scoped_list.instances:
                if instance.status != "RUNNING":
                    continue

                ip = self._get_primary_ip(instance)
                labels = dict(instance.labels) if instance.labels else {}

                entries.append(
                    HostEntry(
                        hostname=instance.name,
                        ansible_host=ip,
                        provider="gcp",
                        region=region,
                        zone=zone_name,
                        instance_id=str(instance.id),
                        instance_type=instance.machine_type.split("/")[-1],
                        state=instance.status,
                        tags=labels,
                    )
                )

        logger.info("GCP: found %d running instances in %s", len(entries), self.project)
        return entries

    @staticmethod
    def _get_primary_ip(instance: Any) -> str:
        """Extract the primary internal IP from a GCP instance."""
        for iface in instance.network_interfaces or []:
            if iface.network_i_p:
                return iface.network_i_p
        return ""


# ---------------------------------------------------------------------------
# AWS provider
# ---------------------------------------------------------------------------

class AWSInventoryProvider(InventoryProvider):
    """Fetches EC2 instances from one or more AWS regions."""

    def __init__(
        self,
        regions: list[str] | None = None,
        profile: str | None = None,
    ) -> None:
        self.regions = regions or ["us-east-1"]
        self.profile = profile

    def provider_name(self) -> str:
        return "aws"

    def list_instances(self) -> list[HostEntry]:
        try:
            import boto3  # type: ignore[import-untyped]
        except ImportError:
            logger.error("boto3 is not installed. Install with: pip install boto3")
            raise

        session = boto3.Session(profile_name=self.profile) if self.profile else boto3.Session()
        entries: list[HostEntry] = []

        for region in self.regions:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_instances")

            filters = [{"Name": "instance-state-name", "Values": ["running"]}]

            for page in paginator.paginate(Filters=filters):
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        tags = {
                            t["Key"]: t["Value"]
                            for t in inst.get("Tags", [])
                        }
                        name = tags.get("Name", inst["InstanceId"])
                        ip = inst.get("PrivateIpAddress", "")

                        entries.append(
                            HostEntry(
                                hostname=name,
                                ansible_host=ip,
                                provider="aws",
                                region=region,
                                zone=inst.get("Placement", {}).get(
                                    "AvailabilityZone", region
                                ),
                                instance_id=inst["InstanceId"],
                                instance_type=inst.get("InstanceType", ""),
                                state=inst["State"]["Name"],
                                tags=tags,
                            )
                        )

            logger.info("AWS %s: found %d running instances", region, len(entries))

        return entries


# ---------------------------------------------------------------------------
# Inventory builder
# ---------------------------------------------------------------------------

PROVIDER_REGISTRY: dict[str, type[InventoryProvider]] = {
    "gcp": GCPInventoryProvider,
    "aws": AWSInventoryProvider,
}


def build_ansible_inventory(
    hosts: list[HostEntry],
    group_by_keys: list[str] | None = None,
    default_vars: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Convert a flat list of hosts into Ansible JSON inventory.

    Groups hosts by:
        - provider (gcp, aws)
        - region
        - tag values for each key in group_by_keys
        - special "all" group

    Args:
        hosts: Normalized host entries.
        group_by_keys: Tag keys to create groups from (e.g. ["environment", "role"]).
        default_vars: Default host variables applied to all hosts.

    Returns:
        Ansible-compatible inventory dict.
    """
    group_by_keys = group_by_keys or ["environment", "role"]
    default_vars = default_vars or {}

    inventory: dict[str, Any] = {
        "_meta": {"hostvars": {}},
        "all": {"children": []},
    }

    group_members: dict[str, set[str]] = {}

    def _ensure_group(name: str) -> None:
        safe = _sanitize_group_name(name)
        if safe not in inventory:
            inventory[safe] = {"hosts": [], "vars": {}}
            if safe != "all":
                inventory["all"]["children"].append(safe)
        group_members.setdefault(safe, set())

    for host in hosts:
        hostname = host.hostname

        # Host vars
        hostvars: dict[str, Any] = {
            "ansible_host": host.ansible_host,
            "cloud_provider": host.provider,
            "cloud_region": host.region,
            "cloud_zone": host.zone,
            "instance_id": host.instance_id,
            "instance_type": host.instance_type,
            **default_vars,
            **host.host_vars,
        }
        inventory["_meta"]["hostvars"][hostname] = hostvars

        # Group by provider
        _ensure_group(host.provider)
        if hostname not in group_members[host.provider]:
            inventory[host.provider]["hosts"].append(hostname)
            group_members[host.provider].add(hostname)

        # Group by region
        region_group = f"{host.provider}_{host.region}"
        _ensure_group(region_group)
        if hostname not in group_members[region_group]:
            inventory[region_group]["hosts"].append(hostname)
            group_members[region_group].add(hostname)

        # Group by tag keys
        for key in group_by_keys:
            value = host.tags.get(key)
            if value:
                tag_group = f"{key}_{value}"
                _ensure_group(tag_group)
                if hostname not in group_members[tag_group]:
                    inventory[tag_group]["hosts"].append(hostname)
                    group_members[tag_group].add(hostname)

    # Deduplicate children list
    inventory["all"]["children"] = sorted(set(inventory["all"]["children"]))

    return inventory


def _sanitize_group_name(name: str) -> str:
    """Convert a string into a valid Ansible group name."""
    return name.lower().replace("-", "_").replace(".", "_").replace("/", "_")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate Ansible dynamic inventory from cloud provider APIs.",
    )

    # Ansible integration flags
    parser.add_argument(
        "--list",
        action="store_true",
        help="Output full inventory (required by Ansible)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Output variables for a single host (required by Ansible)",
    )

    # Provider selection
    parser.add_argument(
        "--provider",
        choices=["gcp", "aws", "all"],
        default="all",
        help="Cloud provider to query (default: all)",
    )

    # GCP options
    parser.add_argument(
        "--project",
        default=os.getenv("GCP_PROJECT", ""),
        help="GCP project ID (or set GCP_PROJECT env var)",
    )

    # AWS options
    parser.add_argument(
        "--aws-profile",
        default=os.getenv("AWS_PROFILE"),
        help="AWS CLI profile name (or set AWS_PROFILE env var)",
    )
    parser.add_argument(
        "--regions",
        default=None,
        help="Comma-separated cloud regions to query",
    )

    # Grouping
    parser.add_argument(
        "--group-by",
        default="environment,role",
        help="Comma-separated tag keys to group hosts by (default: environment,role)",
    )

    # Output
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output file path (default: stdout)",
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
        stream=sys.stderr,  # keep stdout clean for Ansible
    )

    # Ansible --host mode: return empty vars (all vars are in _meta)
    if args.host:
        print(json.dumps({}))
        return 0

    providers_to_query: list[str] = (
        ["gcp", "aws"] if args.provider == "all" else [args.provider]
    )
    regions = [r.strip() for r in args.regions.split(",")] if args.regions else None

    all_hosts: list[HostEntry] = []

    for provider_name in providers_to_query:
        try:
            if provider_name == "gcp":
                if not args.project:
                    logger.warning("Skipping GCP: no --project specified.")
                    continue
                provider = GCPInventoryProvider(
                    project=args.project, zones=None
                )
            elif provider_name == "aws":
                provider = AWSInventoryProvider(
                    regions=regions or ["us-east-1"],
                    profile=args.aws_profile,
                )
            else:
                logger.warning("Unknown provider: %s", provider_name)
                continue

            hosts = provider.list_instances()
            all_hosts.extend(hosts)
        except Exception:
            logger.exception("Failed to query provider: %s", provider_name)

    group_by_keys = [k.strip() for k in args.group_by.split(",")]
    inventory = build_ansible_inventory(all_hosts, group_by_keys=group_by_keys)

    inventory_json = json.dumps(inventory, indent=2, sort_keys=True)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(inventory_json)
        logger.info("Inventory written to %s (%d hosts)", args.output, len(all_hosts))
    else:
        print(inventory_json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
