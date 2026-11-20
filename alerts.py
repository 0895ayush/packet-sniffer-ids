import logging
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping, Optional, Tuple

import requests

import config


logger = logging.getLogger(__name__)


class AlertManager:
    """Persist alerts locally and optionally send them to configured webhooks."""

    def __init__(self, database_path: Path = config.DATABASE_PATH) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.database_path), timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_database(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    source_ip TEXT,
                    details TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_created_at "
                "ON alerts(created_at)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS traffic_metrics (
                    bucket_start TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    packet_count INTEGER NOT NULL,
                    byte_count INTEGER NOT NULL,
                    PRIMARY KEY (bucket_start, protocol)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS host_traffic (
                    bucket_start TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    peer_ip TEXT NOT NULL,
                    dest_port INTEGER NOT NULL,
                    packet_count INTEGER NOT NULL,
                    byte_count INTEGER NOT NULL,
                    PRIMARY KEY (
                        bucket_start, target_id, direction, protocol, peer_ip, dest_port
                    )
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_host_traffic_target_time "
                "ON host_traffic(target_id, bucket_start)"
            )

    def log_alert(
        self,
        alert_type: str,
        details: str,
        source_ip: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> int:
        created_at = timestamp or datetime.now(timezone.utc)
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        created_at_text = created_at.astimezone(timezone.utc).isoformat()

        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """
                INSERT INTO alerts (created_at, alert_type, source_ip, details)
                VALUES (?, ?, ?, ?)
                """,
                (created_at_text, alert_type, source_ip, details),
            )
            alert_id = int(cursor.lastrowid)

        message = f"[ALERT] {alert_type}"
        if source_ip:
            message += f" source={source_ip}"
        message += f": {details}"
        logger.warning(message)
        self._send_webhooks(message)
        return alert_id

    def get_recent_alerts(self, limit: int = 100) -> list[dict]:
        if limit < 1:
            raise ValueError("limit must be greater than zero")
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT id, created_at, alert_type, source_ip, details
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_traffic_batch(
        self,
        bucket_timestamp: float,
        metrics: Mapping[str, Tuple[int, int]],
    ) -> None:
        if not metrics:
            return
        bucket_start = datetime.fromtimestamp(
            bucket_timestamp, timezone.utc
        ).isoformat()
        records = [
            (bucket_start, protocol, packet_count, byte_count)
            for protocol, (packet_count, byte_count) in metrics.items()
            if packet_count > 0
        ]
        if not records:
            return
        with closing(self._connect()) as connection, connection:
            connection.executemany(
                """
                INSERT INTO traffic_metrics
                    (bucket_start, protocol, packet_count, byte_count)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(bucket_start, protocol) DO UPDATE SET
                    packet_count = packet_count + excluded.packet_count,
                    byte_count = byte_count + excluded.byte_count
                """,
                records,
            )

    def get_traffic_metrics(self, since_seconds: int = 60) -> list[dict]:
        if since_seconds < 1:
            raise ValueError("since_seconds must be greater than zero")
        since = (datetime.now(timezone.utc) - timedelta(seconds=since_seconds)).isoformat()
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT bucket_start, protocol, packet_count, byte_count
                FROM traffic_metrics
                WHERE bucket_start >= ?
                ORDER BY bucket_start ASC, protocol ASC
                """,
                (since,),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_host_traffic_batch(
        self,
        bucket_timestamp: float,
        metrics: Mapping[
            Tuple[str, str, str, str, int],
            Tuple[int, int],
        ],
    ) -> None:
        if not metrics:
            return
        bucket_start = datetime.fromtimestamp(
            bucket_timestamp, timezone.utc
        ).isoformat()
        records = [
            (
                bucket_start,
                target_id,
                direction,
                protocol,
                peer_ip,
                dest_port,
                packet_count,
                byte_count,
            )
            for (
                target_id,
                direction,
                protocol,
                peer_ip,
                dest_port,
            ), (packet_count, byte_count) in metrics.items()
            if packet_count > 0
        ]
        if not records:
            return
        with closing(self._connect()) as connection, connection:
            connection.executemany(
                """
                INSERT INTO host_traffic (
                    bucket_start, target_id, direction, protocol, peer_ip,
                    dest_port, packet_count, byte_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (
                    bucket_start, target_id, direction, protocol, peer_ip, dest_port
                ) DO UPDATE SET
                    packet_count = packet_count + excluded.packet_count,
                    byte_count = byte_count + excluded.byte_count
                """,
                records,
            )

    def get_host_traffic(
        self,
        target_id: Optional[str] = None,
        since_seconds: int = 300,
    ) -> list[dict]:
        if since_seconds < 1:
            raise ValueError("since_seconds must be greater than zero")
        since = (datetime.now(timezone.utc) - timedelta(seconds=since_seconds)).isoformat()
        with closing(self._connect()) as connection:
            if target_id is None:
                rows = connection.execute(
                    """
                    SELECT bucket_start, target_id, direction, protocol, peer_ip,
                           dest_port, packet_count, byte_count
                    FROM host_traffic
                    WHERE bucket_start >= ?
                    ORDER BY bucket_start ASC, target_id ASC
                    """,
                    (since,),
                ).fetchall()
            else:
                normalized_target = config.normalize_watch_target(target_id)
                rows = connection.execute(
                    """
                    SELECT bucket_start, target_id, direction, protocol, peer_ip,
                           dest_port, packet_count, byte_count
                    FROM host_traffic
                    WHERE target_id = ? AND bucket_start >= ?
                    ORDER BY bucket_start ASC, target_id ASC
                    """,
                    (normalized_target, since),
                ).fetchall()
        return [dict(row) for row in rows]

    def _send_webhooks(self, message: str) -> None:
        if config.SLACK_WEBHOOK_URL:
            self._post_webhook(
                config.SLACK_WEBHOOK_URL,
                {"text": message},
                "Slack",
            )
        if config.DISCORD_WEBHOOK_URL:
            self._post_webhook(
                config.DISCORD_WEBHOOK_URL,
                {"content": message},
                "Discord",
            )

    @staticmethod
    def _post_webhook(url: str, payload: dict, service: str) -> None:
        try:
            response = requests.post(
                url,
                json=payload,
                timeout=config.WEBHOOK_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
        except requests.RequestException:
            logger.exception("%s alert webhook delivery failed", service)
