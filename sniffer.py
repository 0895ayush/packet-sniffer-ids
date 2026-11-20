import logging
import os
from importlib import import_module
from pathlib import Path
from queue import Queue
from threading import Lock
from typing import Any, Optional, Union

import config


logger = logging.getLogger(__name__)
_WINDOWS_CAPTURE_GUIDANCE = (
    "If you are on Windows, install Npcap with "
    "'WinPcap API-compatible Mode' enabled, or use --pcap for offline replay."
)


class SnifferError(RuntimeError):
    """Raised when packet capture cannot start or complete successfully."""


class CaptureProviderError(RuntimeError):
    """Raised when Scapy has no available live-capture socket provider."""


def _has_layer2_provider() -> bool:
    try:
        from scapy.config import conf
        from scapy.error import Scapy_Exception
    except ImportError:
        return False

    try:
        if os.name == "nt" and not conf.use_pcap:
            conf.use_pcap = True
        if os.name == "nt":
            return bool(conf.use_pcap)
        return bool(conf.use_pcap or conf.L2socket is not None)
    except (AttributeError, OSError, RuntimeError, Scapy_Exception):
        return False


class PacketSniffer:
    """Capture packets asynchronously and enqueue them for a consumer."""

    def __init__(
        self,
        packet_queue: Queue,
        interface: Optional[str] = config.DEFAULT_INTERFACE,
        pcap: Optional[Union[str, Path]] = config.PCAP_PATH,
        layer3: bool = False,
    ) -> None:
        if interface and pcap:
            raise ValueError("Specify either an interface or a PCAP file, not both")

        self.packet_queue = packet_queue
        self.interface = interface
        self.pcap = Path(pcap) if pcap else None
        self.layer3 = layer3
        self._sniffer: Any = None
        self._lock = Lock()
        self._capture_failed = False

    def start(self) -> None:
        with self._lock:
            if self._sniffer is not None:
                raise RuntimeError("Packet sniffer has already been started")
            if self.pcap is not None and not self.pcap.is_file():
                raise FileNotFoundError(f"PCAP file not found: {self.pcap}")
            self._capture_failed = False

            try:
                from scapy.error import Scapy_Exception
                from scapy.sendrecv import AsyncSniffer
            except ImportError as error:
                raise SnifferError(
                    "Scapy is required for packet capture; install requirements.txt"
                ) from error

            for layer in ("dns", "inet", "inet6", "l2"):
                import_module(f"scapy.layers.{layer}")

            options = {"prn": self._enqueue_packet, "store": False}
            opened_socket = None
            try:
                if self.pcap is not None:
                    options["offline"] = str(self.pcap)
                else:
                    use_layer3 = self.layer3
                    if not use_layer3 and not _has_layer2_provider():
                        logger.warning(
                            "Layer-2 capture driver (Npcap/libpcap) not detected; "
                            "automatically falling back to Layer-3 IP socket mode. "
                            "Install Npcap for ARP/Ethernet inspection."
                        )
                        use_layer3 = True

                    if use_layer3:
                        from scapy.config import conf

                        if conf.L3socket is None:
                            raise CaptureProviderError(
                                "No Layer-3 capture socket is available"
                            )
                        opened_socket = conf.L3socket(iface=self.interface)
                        options["opened_socket"] = opened_socket
                    elif self.interface:
                        options["iface"] = self.interface

                self._sniffer = AsyncSniffer(**options)
                self._sniffer.start()
            except CaptureProviderError as error:
                self._capture_failed = True
                self._close_opened_socket(opened_socket, Scapy_Exception)
                self._sniffer = None
                raise SnifferError(str(error)) from error
            except PermissionError as error:
                self._capture_failed = True
                self._close_opened_socket(opened_socket, Scapy_Exception)
                self._sniffer = None
                logger.error(
                    "Packet capture permission denied. Run with administrator/root "
                    "privileges or use PCAP replay."
                )
                raise SnifferError("Permission denied while starting packet capture") from error
            except (OSError, TypeError, ValueError, RuntimeError, Scapy_Exception) as error:
                self._capture_failed = True
                self._close_opened_socket(opened_socket, Scapy_Exception)
                self._sniffer = None
                message = self._capture_failure_message(
                    "Unable to start packet capture", error
                )
                raise SnifferError(message) from error

            try:
                self._raise_capture_error()
            except SnifferError:
                self._capture_failed = True
                raise

    def stop(self) -> None:
        sniffer = self._sniffer
        if sniffer is None or self._capture_failed:
            return
        from scapy.error import Scapy_Exception

        try:
            if sniffer.running:
                try:
                    sniffer.stop(join=True)
                except PermissionError as error:
                    logger.error("Packet capture stopped after a permission error")
                    raise SnifferError("Permission error while stopping packet capture") from error
                except (OSError, ValueError, RuntimeError, Scapy_Exception) as error:
                    message = self._capture_failure_message(
                        "Unable to stop packet capture", error
                    )
                    raise SnifferError(message) from error
            else:
                self._join_sniffer(sniffer, Scapy_Exception)
            self._raise_capture_error()
        except SnifferError:
            self._capture_failed = True
            raise

    def wait(self) -> None:
        """Wait for capture completion; offline PCAP replay ends at EOF."""
        if self._sniffer is None:
            raise RuntimeError("Packet sniffer has not been started")
        from scapy.error import Scapy_Exception

        try:
            self._join_sniffer(self._sniffer, Scapy_Exception)
            self._raise_capture_error()
        except SnifferError:
            self._capture_failed = True
            raise

    @staticmethod
    def _join_sniffer(sniffer: Any, scapy_exception: type[BaseException]) -> None:
        try:
            sniffer.join()
        except PermissionError as error:
            logger.error(
                "Packet capture permission denied. Run with administrator/root "
                "privileges or use PCAP replay."
            )
            raise SnifferError("Permission denied while capturing packets") from error
        except (OSError, ValueError, RuntimeError, scapy_exception) as error:
            message = PacketSniffer._capture_failure_message(
                "Packet capture failed", error
            )
            raise SnifferError(message) from error

    def _enqueue_packet(self, packet: Any) -> None:
        # Queue is intentionally unbounded to avoid dropping captured packets.
        self.packet_queue.put(packet)

    @staticmethod
    def _capture_failure_message(action: str, error: BaseException) -> str:
        return f"{action}: {error}. {_WINDOWS_CAPTURE_GUIDANCE}"

    @staticmethod
    def _close_opened_socket(
        opened_socket: Any,
        scapy_exception: type[BaseException],
    ) -> None:
        if opened_socket is None:
            return
        try:
            opened_socket.close()
        except (OSError, RuntimeError, scapy_exception) as error:
            logger.warning("Unable to close capture socket cleanly: %s", error)

    def _raise_capture_error(self) -> None:
        error = getattr(self._sniffer, "exception", None)
        if error is None:
            return
        if isinstance(error, PermissionError):
            logger.error(
                "Packet capture permission denied. Run with administrator/root "
                "privileges or use PCAP replay."
            )
            raise SnifferError("Permission denied while capturing packets") from error
        message = self._capture_failure_message("Packet capture failed", error)
        raise SnifferError(message) from error
