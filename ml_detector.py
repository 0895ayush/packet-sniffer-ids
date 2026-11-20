import logging
import time
from importlib import import_module
from typing import Any, Iterable, Optional, Tuple


logger = logging.getLogger(__name__)
FlowFeatures = Tuple[float, float, float, float]


class FlowAnomalyDetector:
    """Isolation Forest detector for basic per-packet flow features."""

    def __init__(self) -> None:
        self._model: Any = None
        self._last_seen: dict[tuple, float] = {}

    def extract_features(
        self, packet: Any, timestamp: Optional[float] = None
    ) -> FlowFeatures:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6

        packet_time = timestamp
        if packet_time is None:
            packet_time = float(getattr(packet, "time", time.time()))

        if packet.haslayer(IP):
            network = packet[IP]
            protocol_id = float(network.proto)
            source = network.src
            destination = network.dst
        elif packet.haslayer(IPv6):
            network = packet[IPv6]
            protocol_id = float(network.nh)
            source = network.src
            destination = network.dst
        else:
            protocol_id = 0.0
            source = "unknown"
            destination = "unknown"

        destination_port = 0
        if packet.haslayer(TCP):
            destination_port = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            destination_port = int(packet[UDP].dport)

        flow_key = (source, destination, protocol_id, destination_port)
        previous_time = self._last_seen.get(flow_key)
        inter_arrival = (
            max(0.0, packet_time - previous_time)
            if previous_time is not None
            else 0.0
        )
        self._last_seen[flow_key] = packet_time

        return (
            float(len(packet)),
            inter_arrival,
            protocol_id,
            float(destination_port),
        )

    def fit(self, features: Iterable[FlowFeatures]) -> int:
        rows = list(features)
        if len(rows) < 2:
            raise ValueError("At least two baseline packets are required to train")
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError as error:
            raise RuntimeError(
                "scikit-learn is required for ML detection; install requirements.txt"
            ) from error

        model = IsolationForest(
            n_estimators=100,
            contamination="auto",
            random_state=42,
        )
        model.fit(rows)
        self._model = model
        logger.info("Trained Isolation Forest on %d packets", len(rows))
        return len(rows)

    @property
    def is_trained(self) -> bool:
        return self._model is not None

    def is_anomaly(self, features: FlowFeatures) -> bool:
        if self._model is None:
            return False
        return bool(self._model.predict([features])[0] == -1)


def extract_pcap_features(pcap_path: str) -> list[FlowFeatures]:
    try:
        from scapy.utils import PcapReader
    except ImportError as error:
        raise RuntimeError(
            "Scapy is required to read PCAP files; install requirements.txt"
        ) from error

    for layer in ("dns", "inet", "inet6", "l2"):
        import_module(f"scapy.layers.{layer}")

    detector = FlowAnomalyDetector()
    features: list[FlowFeatures] = []
    with PcapReader(pcap_path) as reader:
        for packet in reader:
            features.append(detector.extract_features(packet))
    return features
