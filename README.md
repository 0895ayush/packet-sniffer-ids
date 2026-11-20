# packet-sniffer-ids (NetGuard IDS)

NetGuard IDS is a modular, multi-threaded Python packet sniffer and intrusion-detection demo featuring real-time rule-based detections, Isolation Forest ML anomaly detection, target IP/MAC tracking, and a live Streamlit SOC dashboard. It captures live traffic with Scapy or replays PCAP files, analyzes packets on a separate consumer thread, records traffic metrics and alerts in SQLite, and presents a local dashboard.

The project is intended for defensive monitoring and offline testing. The included test-traffic generator writes packets to a PCAP file only; it does not transmit packets.

## Features

- **Producer-consumer capture:** Scapy's `AsyncSniffer` places captured packets on an unbounded `queue.Queue`; a dedicated analyzer thread consumes them.
- **Rule-based detections:**
  - TCP port scan: more than 15 unique destination ports from one source within 5 seconds.
  - ARP spoofing: an ARP reply changes the observed MAC address for an IP.
  - SYN flood: more than 100 TCP SYN-without-ACK packets from one source within 2 seconds.
  - Cleartext HTTP credentials: HTTP POST payloads containing `password=`, `passwd=`, or `user=`.
  - Suspicious DNS: a label longer than 50 characters or with Shannon entropy above 4.0.
- **ML anomaly detection:** an Isolation Forest uses packet size, inter-arrival time, IP protocol ID, and destination port to flag traffic that differs from the supplied baseline.
- **Alerting and persistence:** alerts are written to SQLite and logged to the console; optional Slack and Discord webhooks can forward alert summaries.
- **Per-target tracking:** select IP addresses or MAC addresses to record inbound/outbound packet and byte totals, peer IPs, and destination ports.
- **SOC-style dashboard:** Streamlit displays recent traffic volume, protocol distribution, packets per second, alert history, and watched-target activity.
- **Offline workflow:** replay PCAPs and run the generated test fixture without administrator/root privileges.

## Architecture

```text
                         +----------------------+
                         | Live interface or    |
                         | offline PCAP         |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Scapy AsyncSniffer   |
                         | producer thread      |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | queue.Queue          |
                         | capture / analysis   |
                         | boundary             |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | PacketAnalyzer       |
                         | consumer thread     |
                         +----+------------+----+
                              |            |
                    IDS rules |            | flow features
                              |            v
                              |   +----------------------+
                              |   | Isolation Forest    |
                              |   | ML detector         |
                              |   +----------+-----------+
                              |              |
                              +------+-------+
                                     |
                  alerts + traffic metrics
                  + per-target traffic
                                     |
                +--------------------+--------------------+
                |                                         |
                v                                         v
      +----------------------+                  +----------------------+
      | SQLite database      |<-----------------| Streamlit dashboard  |
      | alerts + metrics     |   reads data     | charts + target log  |
      +----------+-----------+                  +----------------------+
                 |
                 +------> Console / optional Slack / Discord
```

## Project layout

```text
netguard-ids/
├── .gitignore
├── alerts.py
├── analyzer.py
├── config.py
├── dashboard.py
├── generate_test_pcap.py
├── main.py
├── ml_detector.py
├── README.md
├── requirements.txt
└── sniffer.py
```

## Installation

Requires Python 3.10 or newer.

```bash
git clone <repository-url> netguard-ids
cd netguard-ids
python -m venv .venv
```

Activate the virtual environment:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# macOS / Linux
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

### Windows live capture

Install [Npcap](https://npcap.com/) and select **Install Npcap in WinPcap API-compatible Mode** during setup. Run the terminal as Administrator for live interface capture. Offline PCAP replay does not require live-capture permissions.

## Usage

### Zero-Config Plug & Play

Run `python main.py` to start immediately: NetGuard first attempts live capture, automatically uses a Layer-3 IP socket when Layer-2 capture is unavailable, and, if live capture is blocked by missing privileges or a capture driver, generates `sample_attack.pcap` when needed and runs the offline demo. The offline demo works without administrator/root privileges and produces detections for the dashboard. Use `--strict` to exit with code 1 instead of falling back after a live-capture privilege or driver error. The usual target-tracking prompt may still appear; press Enter to monitor all traffic.

### Quick-start commands

Create and activate a virtual environment, then install the Python dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

For the offline demo, generate and replay the sample PCAP:

```powershell
python generate_test_pcap.py
python main.py --pcap sample_attack.pcap --no-prompt
```

For continuous live capture on Windows, first install Npcap with **WinPcap API-compatible Mode** enabled, then run PowerShell as Administrator. In one terminal, start the dashboard:

```powershell
python -m streamlit run dashboard.py
```

In a second Administrator PowerShell, start capture on the active Wi-Fi interface:

```powershell
python main.py --interface "Wi-Fi" --no-prompt --strict
```

Replace `"Wi-Fi"` with the interface name on your computer. Leave the capture command running; press `Ctrl+C` to stop it. The dashboard reads from the same SQLite database and refreshes automatically.

### Generate offline test traffic

```bash
python generate_test_pcap.py
```

This writes `sample_attack.pcap` next to the script. It contains baseline packets and simulated port-scan, ARP-conflict, SYN-flood, cleartext HTTP POST, and high-entropy DNS examples. It does not send any traffic.

### Replay and analyze the test PCAP

```bash
python main.py --pcap sample_attack.pcap --train-ml
```

Unless `--watch` or `--no-prompt` is supplied, the command prompts:

```text
Enter target IP(s) or Device ID/MAC(s) to track (comma-separated, or press Enter to monitor all):
```

Press Enter to analyze all traffic without per-target tracking, or enter one or more IPv4/IPv6 addresses and MAC addresses. The analyzer records matching inbound/outbound traffic and emits at most one watched-activity alert per target every 60 seconds.

To pass targets explicitly and skip the prompt:

```bash
python main.py --pcap sample_attack.pcap --watch 192.0.2.10 aa-bb-cc-dd-ee-ff
python main.py --pcap sample_attack.pcap --watch 192.0.2.10,aa:bb:cc:dd:ee:ff --no-prompt
python main.py --pcap sample_attack.pcap --no-prompt
```

`--watch` accepts one or more targets and comma-separated lists. With no `--watch`, `python main.py` and `python main.py --pcap sample_attack.pcap` prompt interactively unless `--no-prompt` is present. `NETGUARD_WATCH_TARGETS` values are merged with command-line or prompt targets.

The ML model is fit to the supplied PCAP before replay, and the analyzer runs the rule checks and ML scoring during replay. For meaningful behavioral ML results, train on a representative **clean baseline** PCAP rather than an attack-mixed fixture:

```bash
python main.py --interface "Wi-Fi" --pcap baseline.pcap --train-ml
```

### Capture a live interface

```powershell
# Windows PowerShell (run as Administrator; replace with your interface name)
python main.py --interface "Wi-Fi" --no-prompt --strict
```

Layer-2 availability is checked automatically; if it is unavailable, NetGuard tries Scapy's Layer-3 socket where supported. If live capture is blocked by privileges or a missing provider, it runs the offline demo unless `--strict` is supplied. To request Layer-3 mode directly:

```powershell
python main.py --interface "Wi-Fi" --layer3
```

```bash
# macOS / Linux (replace with your interface name)
sudo python main.py --interface eth0
```

Press `Ctrl+C` to stop capture and shut down the analyzer cleanly. The `--interface` and `--pcap` options may be combined only with `--train-ml`, where the PCAP supplies the baseline and the interface supplies live packets. For example, `python main.py --interface "Wi-Fi" --pcap baseline.pcap --train-ml --watch 192.0.2.10` trains from the baseline, tracks the selected target, and then captures live packets.

### Launch the dashboard

In a second terminal, from the project directory and the same environment:

```bash
python -m streamlit run dashboard.py
```

The dashboard defaults to `http://localhost:8501/` and refreshes its traffic and alert views every two seconds. Its **Target IP / Device ID Tracker** section summarizes watched-target traffic from the last five minutes.

## Configuration

Settings are read from environment variables:

| Variable | Description | Default |
|---|---|---|
| `NETGUARD_INTERFACE` | Default live-capture interface when `--interface` is not supplied. | Scapy default interface |
| `NETGUARD_PCAP` | Default PCAP path for replay, or the baseline PCAP when using `--train-ml`. | None |
| `NETGUARD_WATCH_TARGETS` | Comma-separated IPv4/IPv6 addresses or MAC addresses to track; merged with CLI or prompt targets. | Empty |
| `NETGUARD_WATCH_ALERT_ON_ACTIVITY` | Emit a deduplicated watched-target activity alert (accepted false values: `false`, `0`, `no`, `off`). | `true` |
| `NETGUARD_DATABASE` | SQLite database path for alert and traffic metrics. | `netguard_alerts.sqlite3` |
| `NETGUARD_SLACK_WEBHOOK_URL` | Optional Slack incoming webhook URL. | Disabled |
| `NETGUARD_DISCORD_WEBHOOK_URL` | Optional Discord webhook URL. | Disabled |

Set webhook URLs only in the local environment; do not commit credentials or `.env` files.

## Notes

- The sample PCAP is synthetic and for defensive, offline testing only.
- The HTTP rule can inspect only unencrypted HTTP payloads visible to the capture point; it cannot read HTTPS application data.
- An Isolation Forest is an anomaly-scoring aid, not a replacement for a tuned baseline or analyst review.
- Live capture availability depends on platform capture drivers and privileges. On Windows, install Npcap as described above.
