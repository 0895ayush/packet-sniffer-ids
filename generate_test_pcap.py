import time
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap


def build_test_packets() -> list[Packet]:
    packets: list[Packet] = []
    start_time = time.time()

    def add(packet: Packet, offset: float) -> None:
        packet.time = start_time + offset
        packets.append(packet)

    add(
        Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, psrc="192.0.2.1", pdst="192.0.2.254"),
        0.0,
    )
    add(
        Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="192.0.2.1", dst="198.51.100.10")
        / TCP(sport=41000, dport=443, flags="A")
        / Raw(load=b"baseline-https-metadata"),
        0.01,
    )
    add(
        Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="192.0.2.1", dst="198.51.100.53")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="www.example.com")),
        0.02,
    )
    add(
        Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="192.0.2.1", dst="198.51.100.10")
        / ICMP(),
        0.03,
    )
    add(
        Ether(src="02:00:00:00:00:02", dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=2,
            hwsrc="02:00:00:00:00:02",
            psrc="192.0.2.50",
            hwdst="ff:ff:ff:ff:ff:ff",
            pdst="192.0.2.1",
        ),
        0.04,
    )

    for index in range(21):
        add(
            Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20")
            / IP(src="192.0.2.10", dst="198.51.100.20")
            / TCP(sport=42000, dport=1000 + index, flags="S"),
            0.10 + index * 0.005,
        )

    add(
        Ether(src="02:00:00:00:00:50", dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=2,
            hwsrc="02:00:00:00:00:50",
            psrc="192.0.2.50",
            hwdst="ff:ff:ff:ff:ff:ff",
            pdst="192.0.2.1",
        ),
        0.25,
    )

    for index in range(101):
        add(
            Ether(src="02:00:00:00:00:30", dst="02:00:00:00:00:40")
            / IP(src="192.0.2.30", dst="198.51.100.40")
            / TCP(sport=20000 + index, dport=443, flags="S"),
            0.30 + index * 0.005,
        )

    add(
        Ether(src="02:00:00:00:00:60", dst="02:00:00:00:00:70")
        / IP(src="192.0.2.60", dst="198.51.100.70")
        / TCP(sport=43000, dport=80, flags="PA")
        / Raw(
            load=(
                b"POST /demo HTTP/1.1\r\n"
                b"Host: example.test\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                b"user=demo&password=not-a-real-password"
            )
        ),
        0.85,
    )

    high_entropy_label = (
        "a9f3c7e2b1d6h4k8m0p5q7r9s2t6v1w3"
        "a4b5c6d7e8f9g0h1i2j3k4l5"
    )
    add(
        Ether(src="02:00:00:00:00:80", dst="02:00:00:00:00:53")
        / IP(src="192.0.2.80", dst="198.51.100.53")
        / UDP(sport=53080, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=f"{high_entropy_label}.example.com")),
        0.90,
    )

    packets.sort(key=lambda packet: float(packet.time))
    return packets


def main() -> None:
    output_path = Path(__file__).resolve().with_name("sample_attack.pcap")
    packets = build_test_packets()
    wrpcap(str(output_path), packets)
    print(f"Wrote {len(packets)} offline test packets to {output_path}")


if __name__ == "__main__":
    main()
