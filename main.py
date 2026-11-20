import argparse
import errno
import logging
from pathlib import Path
from queue import Queue
from typing import Optional, Sequence

from alerts import AlertManager
from analyzer import PacketAnalyzer
from ml_detector import FlowAnomalyDetector, extract_pcap_features
from sniffer import CaptureProviderError, PacketSniffer, SnifferError
import config


logger = logging.getLogger("netguard")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture network traffic and analyze it for suspicious activity."
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface to capture (requires capture permissions).",
    )
    parser.add_argument(
        "--pcap",
        default=None,
        help="PCAP to replay, or baseline PCAP when used with --interface --train-ml.",
    )
    parser.add_argument(
        "--train-ml",
        action="store_true",
        help="Train from --pcap before replay, or before live capture with --interface.",
    )
    parser.add_argument(
        "--watch",
        nargs="+",
        metavar="TARGET",
        help="IP address or MAC address to track; accepts multiple targets or comma-separated values.",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Skip the interactive target prompt and use only configured/CLI targets.",
    )
    parser.add_argument(
        "--layer3",
        action="store_true",
        help="Use Scapy's Layer-3 socket for live capture where supported.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit on live-capture permission or driver errors instead of using the offline demo.",
    )
    return parser


def _is_permission_or_driver_error(error: BaseException) -> bool:
    current: Optional[BaseException] = error
    first = True
    permission_messages = (
        "permission denied",
        "operation not permitted",
        "access is denied",
        "insufficient privilege",
        "must be run as root",
    )
    driver_messages = (
        "npcap",
        "winpcap",
        "libpcap",
        "no pcap provider",
        "pcap provider",
        "layer-2 capture driver",
        "layer 2 capture driver",
    )

    while current is not None:
        if isinstance(current, CaptureProviderError):
            return True
        if isinstance(current, PermissionError):
            return True
        if isinstance(current, OSError) and current.errno in {
            errno.EACCES,
            errno.EPERM,
        }:
            return True

        message = str(current).lower()
        if any(phrase in message for phrase in permission_messages):
            return True
        if not (first and isinstance(error, SnifferError)) and any(
            phrase in message for phrase in driver_messages
        ):
            return True

        current = current.__cause__ or current.__context__
        first = False

    return False


def parse_watch_targets(values: Sequence[str]) -> set[str]:
    targets: set[str] = set()
    for value in values:
        for candidate in value.split(","):
            if candidate.strip():
                targets.add(config.normalize_watch_target(candidate))
    return targets


def run(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.interface and args.pcap and not args.train_ml:
        parser.error("--interface with --pcap requires --train-ml")

    baseline_pcap = args.pcap or config.PCAP_PATH
    if args.train_ml and not baseline_pcap:
        parser.error("--train-ml requires --pcap (or NETGUARD_PCAP)")

    watch_values = list(config.WATCH_TARGETS)
    if args.watch is not None:
        watch_values.extend(args.watch)
    elif not args.no_prompt:
        try:
            watch_values.append(
                input(
                    "Enter target IP(s) or Device ID/MAC(s) to track "
                    "(comma-separated, or press Enter to monitor all): "
                )
            )
        except EOFError:
            logger.warning(
                "No interactive input is available; continuing with configured "
                "watch targets only. Use --no-prompt to disable this prompt."
            )
        except KeyboardInterrupt:
            logger.info("Startup cancelled")
            return 0

    try:
        watch_targets = parse_watch_targets(watch_values)
    except ValueError as error:
        parser.error(str(error))
    if args.watch is not None and not watch_targets:
        parser.error("--watch requires at least one valid IP or MAC address")
    if watch_targets:
        logger.info("Tracking targets: %s", ", ".join(sorted(watch_targets)))
    else:
        logger.info("No watch targets configured; monitoring all traffic")

    interface = args.interface or (
        None if baseline_pcap else config.DEFAULT_INTERFACE
    )
    capture_pcap = baseline_pcap if args.interface is None else None

    detector = FlowAnomalyDetector()
    if args.train_ml:
        count = detector.fit(extract_pcap_features(str(baseline_pcap)))
        logger.info(
            "Trained ML baseline from %d packets in %s", count, baseline_pcap
        )

    packet_queue: Queue = Queue()
    alert_manager = AlertManager()
    analyzer = PacketAnalyzer(
        packet_queue,
        alert_manager,
        detector,
        watch_targets=watch_targets,
    )
    sniffer = PacketSniffer(
        packet_queue,
        interface=interface,
        pcap=capture_pcap,
        layer3=args.layer3,
    )

    analyzer.start()
    try:
        try:
            sniffer.start()
            if capture_pcap:
                logger.info("Replaying PCAP: %s", capture_pcap)
            else:
                logger.info(
                    "Capturing on %s; press Ctrl+C to stop",
                    interface or "default interface",
                )
            sniffer.wait()
            if capture_pcap:
                logger.info("PCAP replay complete")
        except (PermissionError, SnifferError, OSError) as error:
            if capture_pcap or args.strict or not _is_permission_or_driver_error(error):
                raise

            demo_pcap = Path(__file__).resolve().with_name("sample_attack.pcap")
            logger.warning(
                "Insufficient privileges for live capture; automatically running "
                "offline demo with sample_attack.pcap"
            )
            if not demo_pcap.is_file():
                from generate_test_pcap import main as generate_test_pcap

                generate_test_pcap()

            sniffer = PacketSniffer(packet_queue, interface=None, pcap=demo_pcap)
            sniffer.start()
            logger.info("Replaying PCAP: %s", demo_pcap)
            sniffer.wait()
            logger.info("PCAP replay complete")
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
    except PermissionError:
        logger.error(
            "Packet capture permission denied. Run as Administrator or use --pcap."
        )
        return 1
    except (FileNotFoundError, SnifferError, OSError) as error:
        logger.error("%s", error)
        return 1
    finally:
        try:
            sniffer.stop()
        except RuntimeError as error:
            logger.error("Capture shutdown failed: %s", error)
        analyzer.stop()
        analyzer.join()

    if analyzer.error:
        raise RuntimeError("Packet analyzer failed") from analyzer.error
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
