import ipaddress
import os
from pathlib import Path


PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW_SECONDS = 5
SYN_FLOOD_THRESHOLD = 100
SYN_FLOOD_WINDOW_SECONDS = 2
DNS_SUBDOMAIN_LENGTH_THRESHOLD = 50
DNS_ENTROPY_THRESHOLD = 4.0

DEFAULT_INTERFACE = os.environ.get("NETGUARD_INTERFACE") or None
PCAP_PATH = os.environ.get("NETGUARD_PCAP") or None
WATCH_TARGETS = [
    target.strip()
    for target in os.environ.get("NETGUARD_WATCH_TARGETS", "").split(",")
    if target.strip()
]
WATCH_ALERT_ON_ACTIVITY = (
    os.environ.get("NETGUARD_WATCH_ALERT_ON_ACTIVITY", "true").strip().lower()
    not in {"false", "0", "no", "off"}
)
DATABASE_PATH = Path(
    os.environ.get("NETGUARD_DATABASE", "netguard_alerts.sqlite3")
)

SLACK_WEBHOOK_URL = os.environ.get("NETGUARD_SLACK_WEBHOOK_URL") or None
DISCORD_WEBHOOK_URL = os.environ.get("NETGUARD_DISCORD_WEBHOOK_URL") or None
WEBHOOK_TIMEOUT_SECONDS = 5


def normalize_watch_target(target: str) -> str:
    value = target.strip()
    if not value:
        raise ValueError("watch targets cannot be empty")

    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        compact_mac = value.lower().replace(":", "").replace("-", "").replace(".", "")
        if len(compact_mac) == 12 and all(
            character in "0123456789abcdef" for character in compact_mac
        ):
            return ":".join(
                compact_mac[index : index + 2] for index in range(0, 12, 2)
            )
        raise ValueError(
            f"invalid watch target {target!r}; expected an IPv4/IPv6 address or MAC"
        ) from None
