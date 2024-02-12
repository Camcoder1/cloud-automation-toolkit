#!/usr/bin/env python3
"""VMware vSphere Inventory Sync

Connects to a vCenter server via pyVmomi and exports a full VM inventory
to JSON or CSV. Designed for periodic CMDB synchronization.

Environment Variables:
    VCENTER_HOST     - vCenter FQDN or IP
    VCENTER_USER     - vCenter username
    VCENTER_PASSWORD - vCenter password

Usage:
    python vmware_inventory_sync.py --output inventory.json --format json
    python vmware_inventory_sync.py --output inventory.csv --format csv --datacenter DC-Primary
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import ssl
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class VMRecord:
    """Represents a single virtual machine inventory record."""

    name: str
    uuid: str
    power_state: str
    guest_os: str
    cpu_count: int
    memory_mb: int
    disk_total_gb: float
    nics: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    cluster: str = ""
    host: str = ""
    datacenter: str = ""
    resource_pool: str = ""
    folder: str = ""
    annotation: str = ""
    tags: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# vCenter connection abstraction
# ---------------------------------------------------------------------------

class VCenterClient:
    """Abstracted vCenter connection using pyVmomi.

    Wraps SmartConnect / Disconnect and provides high-level inventory
    retrieval so callers never touch raw ManagedObject references.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        verify_ssl: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self._username = username
        self._password = password
        self._verify_ssl = verify_ssl
        self._service_instance: Any = None

    def connect(self) -> None:
        """Establish an authenticated session to vCenter."""
        try:
            from pyVim.connect import SmartConnect
        except ImportError:
            logger.error(
                "pyVmomi is not installed. Install with: pip install pyvmomi"
            )
            raise

        ssl_context: ssl.SSLContext | None = None
        if not self._verify_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        logger.info("Connecting to vCenter %s:%d", self.host, self.port)
        self._service_instance = SmartConnect(
            host=self.host,
            user=self._username,
            pwd=self._password,
            port=self.port,
            sslContext=ssl_context,
        )
        logger.info("Connected successfully.")

    def disconnect(self) -> None:
        """Close the vCenter session."""
        if self._service_instance is None:
            return
        try:
            from pyVim.connect import Disconnect

            Disconnect(self._service_instance)
            logger.info("Disconnected from vCenter.")
        except Exception:
            logger.warning("Error during disconnect; session may have expired.")

    def collect_vms(
        self, datacenter_filter: str | None = None
    ) -> list[VMRecord]:
        """Walk the vCenter inventory tree and return VM records.

        Args:
            datacenter_filter: If set, only VMs in this datacenter are returned.

        Returns:
            A list of VMRecord dataclass instances.
        """
        if self._service_instance is None:
            raise RuntimeError("Not connected. Call connect() first.")

        from pyVmomi import vim  # type: ignore[import-untyped]

        content = self._service_instance.RetrieveContent()
        container = content.rootFolder
        view_type = [vim.VirtualMachine]
        recursive = True

        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )

        records: list[VMRecord] = []
        for vm_obj in container_view.view:
            try:
                record = self._extract_vm_record(vm_obj)
                if datacenter_filter and record.datacenter != datacenter_filter:
                    continue
                records.append(record)
            except Exception:
                logger.warning(
                    "Failed to extract data for VM: %s",
                    getattr(vm_obj, "name", "<unknown>"),
                    exc_info=True,
                )

        container_view.Destroy()
        logger.info("Collected %d VM records.", len(records))
        return records

    @staticmethod
    def _extract_vm_record(vm: Any) -> VMRecord:
        """Extract a VMRecord from a pyVmomi VirtualMachine ManagedObject."""
        config = vm.config
        summary = vm.summary
        guest = vm.guest

        disk_total_kb = sum(
            dev.capacityInKB
            for dev in (config.hardware.device if config else [])
            if hasattr(dev, "capacityInKB")
        )

        nics: list[str] = []
        ip_addresses: list[str] = []
        if guest and guest.net:
            for nic in guest.net:
                if nic.macAddress:
                    nics.append(nic.macAddress)
                if nic.ipAddress:
                    ip_addresses.extend(nic.ipAddress)

        host_name = ""
        cluster_name = ""
        if vm.runtime.host:
            host_name = vm.runtime.host.name
            if vm.runtime.host.parent and hasattr(vm.runtime.host.parent, "name"):
                cluster_name = vm.runtime.host.parent.name

        datacenter_name = ""
        parent = vm.parent
        while parent:
            if parent.__class__.__name__ == "vim.Datacenter":
                datacenter_name = parent.name
                break
            parent = getattr(parent, "parent", None)

        return VMRecord(
            name=vm.name,
            uuid=config.uuid if config else "",
            power_state=str(vm.runtime.powerState),
            guest_os=config.guestFullName if config else "",
            cpu_count=config.hardware.numCPU if config else 0,
            memory_mb=config.hardware.memoryMB if config else 0,
            disk_total_gb=round(disk_total_kb / (1024 * 1024), 2),
            nics=nics,
            ip_addresses=ip_addresses,
            cluster=cluster_name,
            host=host_name,
            datacenter=datacenter_name,
            resource_pool=summary.config.vmPathName if summary else "",
            folder=vm.parent.name if vm.parent else "",
            annotation=config.annotation if config and config.annotation else "",
        )


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_json(records: list[VMRecord], path: str) -> None:
    """Serialize VM records to a JSON file."""
    data = [asdict(r) for r in records]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    logger.info("Wrote %d records to %s", len(data), path)


def write_csv(records: list[VMRecord], path: str) -> None:
    """Serialize VM records to a CSV file."""
    if not records:
        logger.warning("No records to write.")
        return

    flat: list[dict[str, Any]] = []
    for r in records:
        row = asdict(r)
        row["nics"] = "; ".join(row["nics"])
        row["ip_addresses"] = "; ".join(row["ip_addresses"])
        row["tags"] = "; ".join(f"{k}={v}" for k, v in row["tags"].items())
        flat.append(row)

    fieldnames = list(flat[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flat)
    logger.info("Wrote %d records to %s", len(flat), path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export VMware vSphere VM inventory to JSON or CSV.",
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output file path (e.g. inventory.json)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "csv"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--datacenter", "-d",
        default=None,
        help="Filter by datacenter name",
    )
    parser.add_argument(
        "--vcenter-host",
        default=os.getenv("VCENTER_HOST", ""),
        help="vCenter hostname (or set VCENTER_HOST env var)",
    )
    parser.add_argument(
        "--vcenter-port",
        type=int,
        default=443,
        help="vCenter port (default: 443)",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification",
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

    vcenter_host = args.vcenter_host
    vcenter_user = os.getenv("VCENTER_USER", "")
    vcenter_password = os.getenv("VCENTER_PASSWORD", "")

    if not vcenter_host:
        logger.error("vCenter host is required. Set --vcenter-host or VCENTER_HOST.")
        return 1
    if not vcenter_user or not vcenter_password:
        logger.error("Set VCENTER_USER and VCENTER_PASSWORD environment variables.")
        return 1

    client = VCenterClient(
        host=vcenter_host,
        username=vcenter_user,
        password=vcenter_password,
        port=args.vcenter_port,
        verify_ssl=not args.no_verify_ssl,
    )

    try:
        client.connect()
        records = client.collect_vms(datacenter_filter=args.datacenter)
    except Exception:
        logger.exception("Failed to collect VM inventory.")
        return 1
    finally:
        client.disconnect()

    if args.format == "csv":
        write_csv(records, args.output)
    else:
        write_json(records, args.output)

    logger.info("Inventory sync complete. %d VMs exported.", len(records))
    return 0


if __name__ == "__main__":
    sys.exit(main())
