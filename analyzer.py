import logging
import math
import time
from collections import defaultdict, deque
from queue import Empty, Queue
from threading import Event, Thread
from typing import Any, Deque, Dict, Optional, Tuple

import config
from alerts import AlertManager
from ml_detector import FlowAnomalyDetector


logger = logging.getLogger(__name__)
_STOP = object()


class PacketAnalyzer(Thread):
    """Consume queued packets and apply stateful IDS rules."""

    def __init__(
        self,
        packet_queue: Queue,
        alert_manager: AlertManager,
        ml_detector: Optional[FlowAnomalyDetector] = None,
        watch_targets: Optional[set[str]] = None,
    ) -> None:
        super().__init__(name="netguard-analyzer", daemon=True)
        self.packet_queue = packet_queue
        self.alert_manager = alert_manager
        self.ml_detector = ml_detector
        self.watch_targets = {
            config.normalize_watch_target(target)
            for target in (watch_targets or set())
        }
        self._stop_event = Event()
        self.error: Optional[BaseException] = None
        self._port_events: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._scan_alerted: set[str] = set()
        self._syn_events: Dict[str, Deque[float]] = defaultdict(deque)
        self._syn_alerted: set[str] = set()
        self._arp_mappings: dict[str, str] = {}
        self._metrics_bucket: Optional[int] = None
        self._metrics: Dict[str, list[int]] = defaultdict(lambda: [0, 0])
        self._host_metrics: Dict[
            Tuple[str, str, str, str, int], list[int]
        ] = defaultdict(lambda: [0, 0])
        self._last_watch_alert: dict[str, float] = {}

    def stop(self) -> None:
        self._stop_event.set()
        self.packet_queue.put(_STOP)

    def run(self) -> None:
        try:
            while True:
                try:
                    packet = self.packet_queue.get(timeout=0.25)
                except Empty:
                    self._flush_metrics_if_due(force=False)
                    if self._stop_event.is_set():
                        break
                    continue
                try:
                    if packet is _STOP:
                        break
                    self._analyze_packet(packet)
                finally:
                    self.packet_queue.task_done()
                self._flush_metrics_if_due(force=False)
        except BaseException as error:
            self.error = error
            logger.exception("Packet analyzer stopped after an error")
        finally:
            self._flush_metrics_if_due(force=True)

    def _analyze_packet(self, packet: Any) -> None:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import ARP, Ether
        from scapy.packet import Raw

        timestamp = self._packet_timestamp(packet)
        observed_at = time.time()
        protocol = self._protocol_name(packet)
        self._record_metric(protocol, int(len(packet)), observed_at)

        source_ip: Optional[str] = None
        dest_ip: Optional[str] = None
        if packet.haslayer(IP):
            source_ip = str(packet[IP].src)
            dest_ip = str(packet[IP].dst)
        elif packet.haslayer(IPv6):
            source_ip = str(packet[IPv6].src)
            dest_ip = str(packet[IPv6].dst)
        elif packet.haslayer(ARP):
            source_ip = str(packet[ARP].psrc)
            dest_ip = str(packet[ARP].pdst)

        source_mac: Optional[str] = None
        dest_mac: Optional[str] = None
        if packet.haslayer(Ether):
            source_mac = str(packet[Ether].src).lower()
            dest_mac = str(packet[Ether].dst).lower()

        destination_port = 0
        if packet.haslayer(TCP):
            destination_port = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            destination_port = int(packet[UDP].dport)

        self._record_host_traffic(
            source_ip,
            dest_ip,
            source_mac,
            dest_mac,
            protocol,
            destination_port,
            int(len(packet)),
            observed_at,
        )

        if packet.haslayer(ARP):
            self._check_arp(packet[ARP])
        if source_ip and packet.haslayer(TCP):
            tcp = packet[TCP]
            self._check_port_scan(source_ip, int(tcp.dport), timestamp)
            if (int(tcp.flags) & 0x02) and not (int(tcp.flags) & 0x10):
                self._check_syn_flood(source_ip, timestamp)
            if int(tcp.dport) == 80 and packet.haslayer(Raw):
                self._check_http_payload(source_ip, bytes(packet[Raw].load))
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns = packet[DNS]
            if dns.qr == 0:
                self._check_dns_query(source_ip, bytes(packet[DNSQR].qname))
        if self.ml_detector and self.ml_detector.is_trained:
            features = self.ml_detector.extract_features(packet, timestamp)
            if self.ml_detector.is_anomaly(features):
                self.alert_manager.log_alert(
                    "ML traffic anomaly",
                    f"Isolation Forest flagged {protocol} packet "
                    f"({len(packet)} bytes)",
                    source_ip,
                )

    @staticmethod
    def _packet_timestamp(packet: Any) -> float:
        try:
            return float(packet.time)
        except (AttributeError, TypeError, ValueError):
            return time.time()

    @staticmethod
    def _protocol_name(packet: Any) -> str:
        from scapy.layers.dns import DNS
        from scapy.layers.inet import ICMP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import ARP

        if packet.haslayer(ARP):
            return "ARP"
        if packet.haslayer(DNS):
            return "DNS"
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        if packet.haslayer(IPv6):
            return "IPv6"
        return "Other"

    def _check_port_scan(self, source_ip: str, destination_port: int, now: float) -> None:
        events = self._port_events[source_ip]
        events.append((now, destination_port))
        cutoff = now - config.PORT_SCAN_WINDOW_SECONDS
        while events and events[0][0] < cutoff:
            events.popleft()
        unique_ports = {port for _, port in events}
        if len(unique_ports) > config.PORT_SCAN_THRESHOLD:
            if source_ip not in self._scan_alerted:
                self.alert_manager.log_alert(
                    "Port scan",
                    f"{len(unique_ports)} unique destination ports within "
                    f"{config.PORT_SCAN_WINDOW_SECONDS} seconds",
                    source_ip,
                )
                self._scan_alerted.add(source_ip)
        else:
            self._scan_alerted.discard(source_ip)

    def _check_syn_flood(self, source_ip: str, now: float) -> None:
        events = self._syn_events[source_ip]
        events.append(now)
        cutoff = now - config.SYN_FLOOD_WINDOW_SECONDS
        while events and events[0] < cutoff:
            events.popleft()
        if len(events) > config.SYN_FLOOD_THRESHOLD:
            if source_ip not in self._syn_alerted:
                self.alert_manager.log_alert(
                    "SYN flood",
                    f"{len(events)} SYN packets within "
                    f"{config.SYN_FLOOD_WINDOW_SECONDS} seconds",
                    source_ip,
                )
                self._syn_alerted.add(source_ip)
        else:
            self._syn_alerted.discard(source_ip)

    def _check_arp(self, arp: Any) -> None:
        if int(arp.op) != 2:
            return
        ip_address = str(arp.psrc)
        mac_address = str(arp.hwsrc).lower()
        previous_mac = self._arp_mappings.get(ip_address)
        if previous_mac and previous_mac != mac_address:
            self.alert_manager.log_alert(
                "ARP spoofing",
                f"ARP reply maps {ip_address} to {mac_address}; "
                f"previously observed {previous_mac}",
                ip_address,
            )
        self._arp_mappings[ip_address] = mac_address

    def _check_http_payload(self, source_ip: str, payload: bytes) -> None:
        body = payload.lower()
        if not body.startswith(b"post "):
            return
        keywords = (b"password=", b"passwd=", b"user=")
        matches = [keyword.decode("ascii") for keyword in keywords if keyword in body]
        if matches:
            self.alert_manager.log_alert(
                "Cleartext HTTP credentials",
                "HTTP POST payload contains credential-like field(s): "
                + ", ".join(matches),
                source_ip,
            )

    def _check_dns_query(self, source_ip: Optional[str], qname: bytes) -> None:
        name = qname.decode("utf-8", errors="replace").rstrip(".")
        labels = name.split(".")
        suspicious = [
            (label, "long label")
            for label in labels
            if len(label) > config.DNS_SUBDOMAIN_LENGTH_THRESHOLD
        ]
        if not suspicious:
            suspicious = [
                (label, "high entropy")
                for label in labels
                if label and self._shannon_entropy(label) > config.DNS_ENTROPY_THRESHOLD
            ]
        if suspicious:
            label, reason = suspicious[0]
            self.alert_manager.log_alert(
                "Suspicious DNS query",
                f"{reason} ({len(label)} chars, "
                f"entropy {self._shannon_entropy(label):.2f}): {name}",
                source_ip,
            )

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        entropy = 0.0
        for character in set(value):
            probability = value.count(character) / len(value)
            entropy -= probability * math.log2(probability)
        return entropy

    def _record_metric(self, protocol: str, packet_size: int, timestamp: float) -> None:
        bucket = int(timestamp)
        if self._metrics_bucket is None:
            self._metrics_bucket = bucket
        elif bucket != self._metrics_bucket:
            self._flush_metrics_if_due(force=True)
            self._metrics_bucket = bucket
        self._metrics[protocol][0] += 1
        self._metrics[protocol][1] += packet_size

    def _record_host_traffic(
        self,
        source_ip: Optional[str],
        dest_ip: Optional[str],
        source_mac: Optional[str],
        dest_mac: Optional[str],
        protocol: str,
        destination_port: int,
        packet_size: int,
        timestamp: float,
    ) -> None:
        if not self.watch_targets:
            return

        for target in self.watch_targets:
            if target == source_ip or target == source_mac:
                direction = "outbound"
                peer_ip = dest_ip or "unknown"
            elif target == dest_ip or target == dest_mac:
                direction = "inbound"
                peer_ip = source_ip or "unknown"
            else:
                continue

            key = (target, direction, protocol, peer_ip, destination_port)
            self._host_metrics[key][0] += 1
            self._host_metrics[key][1] += packet_size

            if config.WATCH_ALERT_ON_ACTIVITY:
                last_alert = self._last_watch_alert.get(target)
                if last_alert is None or timestamp - last_alert >= 60:
                    self.alert_manager.log_alert(
                        "Watched target activity",
                        f"Target {target} observed {direction} {protocol} traffic "
                        f"with peer {peer_ip} on destination port {destination_port}",
                        source_ip or peer_ip,
                    )
                    self._last_watch_alert[target] = timestamp

    def _flush_metrics_if_due(self, force: bool) -> None:
        if self._metrics_bucket is None or not (
            self._metrics or self._host_metrics
        ):
            return
        if not force and int(time.time()) <= self._metrics_bucket:
            return
        if self._metrics:
            batch = {key: tuple(value) for key, value in self._metrics.items()}
            self.alert_manager.record_traffic_batch(
                float(self._metrics_bucket), batch
            )
        if self._host_metrics:
            host_batch = {
                key: tuple(value) for key, value in self._host_metrics.items()
            }
            self.alert_manager.record_host_traffic_batch(
                float(self._metrics_bucket), host_batch
            )
        self._metrics.clear()
        self._host_metrics.clear()
