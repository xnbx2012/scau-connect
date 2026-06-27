"""Parse aTrust clientResource response into IP resource database.

Reference HAR: ntp.msn.cn_2026_06_24_17_31_17.har

Structure:
  clientResource.data.appList.data.appInfo[].apps[].ext.addressList[]
    → {host: "IP-IP", port: "80-443,3400-65535", protocol: "tcp"}

  Each app also has:
    .id        → appId
    .nodeGroupId → nodeGroupId
    .nodeGroup.addresses → ["192.168.229.31:441", ...]

Target: 222.201.229.3 matches:
  - App "校园应用", appId=dbf7f760-3d5c-11ed-91af-cd04e1aa0123
  - nodeGroupId=d1a68970-a0e5-11ec-bc0a-1f629e1452cd
  - IP range: 222.201.224.1-222.201.255.254
  - Port range: 80-443,3400-65535
  - Node addresses: 192.168.229.31:441 / 219.222.78.12:441 / 202.116.160.23:441
"""

from __future__ import annotations

import re
from typing import Any

from scau_connect.protocol.tunnel.tcp_tunnel_dialer import IPResource, IPResourceDB

__all__ = ["parse_client_resource", "build_default_ip_resource_db"]


def _parse_port_range(port_str: str) -> list[tuple[int, int]]:
    """Parse a port range string like '80-443,3400-65535' into [(80,443), (3400,65535)]."""
    result = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                result.append((int(start.strip()), int(end.strip())))
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                result.append((p, p))
            except ValueError:
                pass
    return result


def _port_in_ranges(port: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= port <= end for start, end in ranges)


def parse_client_resource(raw: dict[str, Any]) -> IPResourceDB:
    """Parse a clientResource response into an IPResourceDB.

    Iterates over all L3VPN apps and extracts IP ranges from ext.addressList.
    """
    db = IPResourceDB()

    app_list = (
        raw.get("data", {})
        .get("appList", {})
        .get("data", {})
        .get("appInfo", [])
    )

    for group in app_list:
        for app in group.get("apps", []):
            access_model = app.get("accessModel", "")
            # Only L3VPN apps use the TCP tunnel
            if access_model not in ("L3VPN", "l3vpn"):
                continue

            app_id = app.get("id", "")
            node_group_id = app.get("nodeGroupId", "")
            ext = app.get("ext", {})
            addr_list = ext.get("addressList", [])

            # Get node addresses from nodeGroup
            node_group = app.get("nodeGroup", {})
            raw_node_addresses = node_group.get("addresses", [])

            # Fall back to node addresses from the parent group
            if not raw_node_addresses:
                parent_id = app.get("groupId", "")
                for parent_group in app_list:
                    if parent_group.get("grpid", "") == parent_id:
                        ng = parent_group.get("nodeGroup", {})
                        raw_node_addresses = ng.get("addresses", [])
                        break

            # Also try nodeGroupV2
            if not raw_node_addresses:
                ng_v2 = app.get("nodeGroupV2", {})
                wan_addrs = ng_v2.get("wan", [])
                if wan_addrs:
                    raw_node_addresses = [a.get("address", "") for a in wan_addrs if a.get("address")]

            # Default node address if none found (all SCAU apps share the same node group)
            if not raw_node_addresses:
                raw_node_addresses = [
                    "192.168.229.31:441",
                    "219.222.78.12:441",
                    "202.116.160.23:441",
                ]

	            # Filter to only known-reachable node addresses.
            # Only 202.116.160.23:441 is confirmed reachable from outside.
            node_addrs = [
                addr for addr in raw_node_addresses
                if addr.startswith("202.116.160.23")
            ]
            if not node_addrs:
                continue

            for addr_entry in addr_list:
                host = addr_entry.get("host", "").strip()
                port_str = addr_entry.get("port", "").strip()
                proto = addr_entry.get("protocol", "tcp").lower()

                if not host or not port_str:
                    continue

                # Skip entries with non-IP hosts (hostnames are for web proxy)
                if not re.match(r"^\d+\.\d+\.\d+\.\d+", host):
                    continue

                for node_addr in node_addrs:
                    res = IPResource(
                        ip_range=host,
                        port_range=port_str,
                        protocol=proto,
                        app_id=app_id,
                        node_group_id=node_group_id,
                        node_address=node_addr,
                    )
                    db.add_resource(res)

    return db


def build_default_ip_resource_db() -> IPResourceDB:
    """Build a pre-populated IP resource database for SCAU VPN.

    These values are extracted from the HAR capture and cover the known
    internal IP ranges. In production this would come from clientResource.
    """
    db = IPResourceDB()

    # SCAU internal IP ranges with their app IDs and node addresses
    # Source: HAR capture from live aTrust session
    # SCAU internal IP ranges with their app IDs and node addresses
    # Source: HAR capture from live aTrust session (2026-06-24)
    #
    # IMPORTANT: These app IDs are from the HAR where the user was authenticated.
    # dbf7f760 (grp dbbac750) is the "校园应用" app with wide IP range.
    # dce31ab0 (grp dbb9dcf0) may give "can not access app in personal space"
    # if not assigned to the user's personal space.
    entries = [
        # 222.201.224.x - 222.201.255.x range (校园应用)
        # app dbf7f760 covers 222.201.224.1-222.201.255.254 - this is the primary app
        # NOTE: nodeGroupId is d1a68970-a0e5-11ec-bc0a-1f629e1452cd (from the HAR).
        # The group-level grpid (dbbac750/dbb9dcf0) is different and NOT used for tunnel auth.
        IPResource(
            ip_range="222.201.224.1-222.201.255.254",
            port_range="80-443,3400-65535",
            protocol="tcp",
            app_id="dbf7f760-3d5c-11ed-91af-cd04e1aa0123",
            node_group_id="d1a68970-a0e5-11ec-bc0a-1f629e1452cd",
            node_address="202.116.160.23:441",
        ),
        # 202.116.160.x range
        IPResource(
            ip_range="202.116.160.1-202.116.160.254",
            port_range="80-443,3400-65535",
            protocol="tcp",
            app_id="dbf7f760-3d5c-11ed-91af-cd04e1aa0123",
            node_group_id="d1a68970-a0e5-11ec-bc0a-1f629e1452cd",
            node_address="202.116.160.23:441",
        ),
        # 202.116.161.x range
        IPResource(
            ip_range="202.116.161.1-202.116.161.254",
            port_range="80-443,3400-65535",
            protocol="tcp",
            app_id="dbf7f760-3d5c-11ed-91af-cd04e1aa0123",
            node_group_id="d1a68970-a0e5-11ec-bc0a-1f629e1452cd",
            node_address="202.116.160.23:441",
        ),
        # 202.116.162.x range
        IPResource(
            ip_range="202.116.162.1-202.116.162.254",
            port_range="80-443,3400-65535",
            protocol="tcp",
            app_id="dbf7f760-3d5c-11ed-91af-cd04e1aa0123",
            node_group_id="d1a68970-a0e5-11ec-bc0a-1f629e1452cd",
            node_address="202.116.160.23:441",
        ),
        # 202.116.163.x range
        IPResource(
            ip_range="202.116.163.1-202.116.163.254",
            port_range="80-443,3400-65535",
            protocol="tcp",
            app_id="dbf7f760-3d5c-11ed-91af-cd04e1aa0123",
            node_group_id="d1a68970-a0e5-11ec-bc0a-1f629e1452cd",
            node_address="202.116.160.23:441",
        ),
        # 202.116.174.x range
        IPResource(
            ip_range="202.116.174.1-202.116.174.254",
            port_range="80-443,3400-65535",
            protocol="tcp",
            app_id="dbf7f760-3d5c-11ed-91af-cd04e1aa0123",
            node_group_id="d1a68970-a0e5-11ec-bc0a-1f629e1452cd",
            node_address="202.116.160.23:441",
        ),
        # 192.168.229.x range (internal campus)
        # NOTE: 192.168.229.31 is internal, but 202.116.160.23:441 is the public gateway
        IPResource(
            ip_range="192.168.229.1-192.168.229.254",
            port_range="80-443,3400-65535",
            protocol="tcp",
            app_id="dbf7f760-3d5c-11ed-91af-cd04e1aa0123",
            node_group_id="d1a68970-a0e5-11ec-bc0a-1f629e1452cd",
            node_address="202.116.160.23:441",
        ),
        # 222.201.228.x - 229.x specific app
        IPResource(
            ip_range="222.201.224.1-222.201.229.254",
            port_range="80-443,3400-65535",
            protocol="tcp",
            app_id="dbf7f760-3d5c-11ed-91af-cd04e1aa0123",
            node_group_id="d1a68970-a0e5-11ec-bc0a-1f629e1452cd",
            node_address="202.116.160.23:441",
        ),
    ]

    for res in entries:
        db.add_resource(res)

    return db
