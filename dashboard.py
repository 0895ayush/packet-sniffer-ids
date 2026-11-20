from collections import defaultdict
from pathlib import Path

import streamlit as st

from alerts import AlertManager
import config


st.set_page_config(page_title="NetGuard IDS", page_icon="🛡️", layout="wide")
st.title("NetGuard IDS")
st.caption("Live traffic metrics and IDS alerts from the local SQLite database.")


@st.fragment(run_every=2)
def render_dashboard() -> None:
    database_path = Path(config.DATABASE_PATH)
    if not database_path.exists():
        st.info("Waiting for NetGuard to write traffic metrics and alerts.")
        return

    manager = AlertManager(database_path)
    traffic = manager.get_traffic_metrics(since_seconds=60)
    alerts = manager.get_recent_alerts(limit=100)
    host_traffic = manager.get_host_traffic(since_seconds=300)

    packets = sum(row["packet_count"] for row in traffic)
    byte_count = sum(row["byte_count"] for row in traffic)
    left, right = st.columns(2)
    left.metric("Packets (last 60 seconds)", f"{packets:,}")
    right.metric("Traffic (last 60 seconds)", f"{byte_count / 1024:.1f} KiB")

    by_protocol: dict[str, int] = defaultdict(int)
    by_second: dict[str, int] = defaultdict(int)
    for row in traffic:
        by_protocol[row["protocol"]] += row["packet_count"]
        second = row["bucket_start"][:19]
        by_second[second] += row["packet_count"]

    chart_column, alert_column = st.columns([1, 2])
    with chart_column:
        st.subheader("Protocol distribution")
        if by_protocol:
            st.bar_chart(by_protocol)
        else:
            st.caption("No recent traffic recorded.")

        st.subheader("Packets per second")
        if by_second:
            st.line_chart(by_second)
        else:
            st.caption("No recent traffic recorded.")

    with alert_column:
        st.subheader("Recent alerts")
        if alerts:
            st.dataframe(alerts, use_container_width=True, hide_index=True)
        else:
            st.caption("No alerts recorded.")

    st.subheader("Target IP / Device ID Tracker")
    configured_targets = {
        config.normalize_watch_target(target) for target in config.WATCH_TARGETS
    }
    recent_targets = {row["target_id"] for row in host_traffic}
    targets = sorted(configured_targets | recent_targets)
    if not targets:
        st.info(
            "No watched targets yet. Start NetGuard with --watch or set "
            "NETGUARD_WATCH_TARGETS."
        )
        return

    selected_target = st.selectbox(
        "Filter by watched target",
        options=["All targets", *targets],
        key="watched_target_filter",
    )
    selected_traffic = (
        host_traffic
        if selected_target == "All targets"
        else [
            row for row in host_traffic
            if row["target_id"] == selected_target
        ]
    )
    inbound_packets = sum(
        row["packet_count"]
        for row in selected_traffic
        if row["direction"] == "inbound"
    )
    outbound_packets = sum(
        row["packet_count"]
        for row in selected_traffic
        if row["direction"] == "outbound"
    )
    total_bytes = sum(row["byte_count"] for row in selected_traffic)
    inbound, outbound, total = st.columns(3)
    inbound.metric("Inbound packets (last 5 minutes)", f"{inbound_packets:,}")
    outbound.metric("Outbound packets (last 5 minutes)", f"{outbound_packets:,}")
    total.metric("Watched traffic", f"{total_bytes / 1024:.1f} KiB")

    peer_stats: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    port_stats: dict[tuple[str, int], int] = defaultdict(int)
    for row in selected_traffic:
        peer_stats[row["peer_ip"]][0] += row["packet_count"]
        peer_stats[row["peer_ip"]][1] += row["byte_count"]
        if row["dest_port"]:
            port_stats[(row["protocol"], row["dest_port"])] += row["packet_count"]

    peer_column, port_column = st.columns(2)
    with peer_column:
        st.markdown("**Top peer IPs**")
        peers = [
            {
                "Peer IP": peer_ip,
                "Packets": counts[0],
                "Bytes": counts[1],
            }
            for peer_ip, counts in sorted(
                peer_stats.items(), key=lambda item: item[1][0], reverse=True
            )[:10]
        ]
        if peers:
            st.dataframe(peers, use_container_width=True, hide_index=True)
        else:
            st.caption("No recent peer traffic for this target.")

    with port_column:
        st.markdown("**Accessed destination ports**")
        ports = [
            {
                "Protocol": protocol,
                "Destination port": destination_port,
                "Packets": packet_count,
            }
            for (protocol, destination_port), packet_count in sorted(
                port_stats.items(), key=lambda item: item[1], reverse=True
            )[:10]
        ]
        if ports:
            st.dataframe(ports, use_container_width=True, hide_index=True)
        else:
            st.caption("No destination ports recorded for this target.")


render_dashboard()
