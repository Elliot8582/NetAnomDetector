#!/usr/bin/env python3
"""
net_anom_detector.py
Live network anomaly detector using Scapy and IsolationForest.

Requirements:
  sudo pip3 install scapy scikit-learn pandas requests python-dateutil
  (On many systems you'll also need libpcap / tshark; scapy uses libpcap)
Run with root privileges (sniffing raw packets).

Design:
  - sniff packets, build ephemeral flows keyed by (src, dst, sport, dport, proto)
  - aggregate features over a sliding window (default 60s)
  - initial baseline collection phase to train IsolationForest (default 180s)
  - after baseline: score new flows, alert if anomaly score below threshold
  - alert via console log, optional SMTP or Slack webhook
"""

import argparse
import logging
import os
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import smtplib
from email.message import EmailMessage
import json
from typing import Deque, Dict, Tuple

import pandas as pd
from dateutil import tz
from sklearn.ensemble import IsolationForest
import requests

from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw

# === Configuration defaults ===
DEFAULT_WINDOW = 60          # seconds for sliding window aggregation
BASELINE_SECONDS = 180      # seconds to collect baseline before detection
RETRAIN_INTERVAL = 3600    # seconds to retrain periodically using stored baseline samples
ANOMALY_THRESHOLD = -0.1   # IsolationForest score threshold (more negative => anomalous)
MAX_FLOW_AGE = 300         # seconds to keep inactive flows
LOG_LEVEL = logging.INFO

# Optional alerting config (fill in on command line or file)
ALERT_CONFIG = {
    "smtp": {
        "enabled": False,
        "server": "smtp.example.com",
        "port": 587,
        "username": "alert@example.com",
        "password": "password",
        "from": "net-anom@example.com",
        "to": ["admin@example.com"]
    },
    "slack": {
        "enabled": False,
        "webhook_url": "https://hooks.slack.com/services/..."
    }
}


# === Data structures ===
@dataclass
class FlowStats:
    first_seen: float
    last_seen: float
    pkt_count: int = 0
    byte_count: int = 0
    tcp_flags_count: int = 0
    src_ports: set = field(default_factory=set)
    dst_ports: set = field(default_factory=set)

    def update(self, pkt_len: int, ts: float, sport=None, dport=None, flags=None):
        self.pkt_count += 1
        self.byte_count += pkt_len
        self.last_seen = ts
        if sport:
            self.src_ports.add(sport)
        if dport:
            self.dst_ports.add(dport)
        if flags:
            # approximate: count non-zero flags
            self.tcp_flags_count += 1 if flags else 0

    def to_feature_vector(self, now_ts: float):
        duration = max(1.0, self.last_seen - self.first_seen)
        avg_pkt_size = self.byte_count / self.pkt_count if self.pkt_count else 0.0
        src_ports = len(self.src_ports)
        dst_ports = len(self.dst_ports)
        pkt_rate = self.pkt_count / duration
        byte_rate = self.byte_count / duration
        time_since_last = now_ts - self.last_seen
        return {
            "duration": duration,
            "pkt_count": self.pkt_count,
            "byte_count": self.byte_count,
            "avg_pkt_size": avg_pkt_size,
            "src_ports": src_ports,
            "dst_ports": dst_ports,
            "pkt_rate": pkt_rate,
            "byte_rate": byte_rate,
            "tcp_flags_count": self.tcp_flags_count,
            "time_since_last": time_since_last
        }


class NetAnomDetector:
    def __init__(self, iface=None, window=DEFAULT_WINDOW,
                 baseline_seconds=BASELINE_SECONDS,
                 anomaly_threshold=ANOMALY_THRESHOLD,
                 alert_config=None):
        self.iface = iface
        self.window = window
        self.baseline_seconds = baseline_seconds
        self.anomaly_threshold = anomaly_threshold
        self.alert_config = alert_config or ALERT_CONFIG
        self.flows: Dict[Tuple, FlowStats] = {}
        self.lock = threading.Lock()

        self.feature_history: Deque[Dict] = deque(maxlen=10000)  # store historical vectors for retraining
        self.model = None
        self.baseline_collected = False
        self.baseline_start_ts = None
        self.last_retrain = time.time()

        # Initialize logger
        self.logger = logging.getLogger("NetAnomDetector")
        self.logger.setLevel(LOG_LEVEL)
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        self.logger.addHandler(ch)

    def start(self):
        self.logger.info("Starting NetAnomDetector (iface=%s)", self.iface or "default")
        self.baseline_start_ts = time.time()
        sniff(prn=self._pkt_handler, iface=self.iface, store=False)

    def _make_flow_key(self, pkt):
        # Support IPv4/IPv6 + TCP/UDP
        ts = time.time()
        if IP in pkt:
            ip = pkt[IP]
            proto = ip.proto
            src = ip.src
            dst = ip.dst
        elif IPv6 in pkt:
            ip = pkt[IPv6]
            proto = ip.nh
            src = ip.src
            dst = ip.dst
        else:
            return None

        sport = None
        dport = None
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            proto_name = "TCP"
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            proto_name = "UDP"
        else:
            proto_name = str(proto)

        key = (src, dst, sport, dport, proto_name)
        return key

    def _pkt_handler(self, pkt):
        ts = time.time()
        pkt_len = len(pkt)
        key = self._make_flow_key(pkt)
        if key is None:
            return

        sport = None
        dport = None
        flags = None
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = int(pkt[TCP].flags)
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        with self.lock:
            if key not in self.flows:
                self.flows[key] = FlowStats(first_seen=ts, last_seen=ts)
            self.flows[key].update(pkt_len=pkt_len, ts=ts, sport=sport, dport=dport, flags=flags)

        # Periodically process windowed features in separate thread (non-blocking)
        # We'll spawn a worker every few seconds to aggregate and score
        # To keep it simple here, call aggregator directly but keep it quick
        try:
            self._process_window(now_ts=ts)
        except Exception as e:
            self.logger.exception("Error in process_window: %s", e)

    def _process_window(self, now_ts: float):
        # Remove stale flows
        stale_keys = []
        with self.lock:
            for k, fs in list(self.flows.items()):
                if now_ts - fs.last_seen > MAX_FLOW_AGE:
                    stale_keys.append(k)
            for k in stale_keys:
                del self.flows[k]

            # Build feature vectors for flows active in window
            feature_rows = []
            for k, fs in self.flows.items():
                if now_ts - fs.last_seen <= self.window:
                    fv = fs.to_feature_vector(now_ts)
                    # attach meta
                    fv_meta = {
                        "key": k,
                        "ts": now_ts,
                        **fv
                    }
                    feature_rows.append(fv_meta)

        if not feature_rows:
            return

        df = pd.DataFrame(feature_rows)
        features = ["duration", "pkt_count", "byte_count", "avg_pkt_size",
                    "src_ports", "dst_ports", "pkt_rate", "byte_rate",
                    "tcp_flags_count", "time_since_last"]

        X = df[features].fillna(0.0).values

        # Baseline phase: collect
        if not self.baseline_collected:
            # collect all samples
            for row in df[features].to_dict(orient="records"):
                self.feature_history.append(row)
            elapsed = now_ts - self.baseline_start_ts
            self.logger.info("Baseline collection: %.1fs / %.1fs samples=%d",
                             elapsed, self.baseline_seconds, len(self.feature_history))
            if elapsed >= self.baseline_seconds and len(self.feature_history) >= 50:
                self._train_model()
            return

        # If model exists, score new flows
        if self.model is None:
            self.logger.warning("Model expected but missing; retraining.")
            self._train_model()
            if self.model is None:
                return

        scores = self.model.decision_function(X)   # higher => normal, lower => anomalous
        for i, score in enumerate(scores):
            if score < self.anomaly_threshold:
                # anomalous
                row = df.iloc[i].to_dict()
                self._handle_anomaly(row, score)

        # append recent samples for future retraining
        for row in df[features].to_dict(orient="records"):
            self.feature_history.append(row)

        # periodic retrain
        if time.time() - self.last_retrain > RETRAIN_INTERVAL and len(self.feature_history) >= 100:
            self.logger.info("Periodic retrain (stored samples=%d)", len(self.feature_history))
            self._train_model()
            self.last_retrain = time.time()

    def _train_model(self):
        # train IsolationForest using stored feature_history
        try:
            if not self.feature_history:
                self.logger.warning("No feature history to train on")
                return
            df = pd.DataFrame(list(self.feature_history))
            features = ["duration", "pkt_count", "byte_count", "avg_pkt_size",
                        "src_ports", "dst_ports", "pkt_rate", "byte_rate",
                        "tcp_flags_count", "time_since_last"]
            df = df[features].fillna(0.0)
            self.logger.info("Training IsolationForest on %d samples", len(df))
            model = IsolationForest(n_estimators=200, contamination='auto', random_state=42, behaviour="new")
            model.fit(df.values)
            self.model = model
            self.baseline_collected = True
            self.logger.info("Model trained successfully")
        except Exception as e:
            self.logger.exception("Training failed: %s", e)

    def _handle_anomaly(self, row: dict, score: float):
        k = row.get("key")
        ts = datetime.fromtimestamp(row.get("ts", time.time()), tz=tz.tzlocal()).isoformat()
        msg = {
            "time": ts,
            "flow": k,
            "score": float(score),
            "details": {k2: float(row[k2]) for k2 in ("duration", "pkt_count", "byte_count", "avg_pkt_size",
                                                      "src_ports", "dst_ports", "pkt_rate", "byte_rate",
                                                      "tcp_flags_count", "time_since_last")}
        }
        text = json.dumps(msg, indent=2)
        self.logger.warning("ANOMALY DETECTED: score=%.4f flow=%s", score, k)
        self.logger.info(text)
        # Alerts
        if self.alert_config.get("smtp", {}).get("enabled", False):
            try:
                self._send_smtp_alert(subject=f"Network Anomaly score={score:.4f}", body=text)
            except Exception:
                self.logger.exception("Failed to send SMTP alert")
        if self.alert_config.get("slack", {}).get("enabled", False):
            try:
                self._send_slack_alert(text)
            except Exception:
                self.logger.exception("Failed to send Slack alert")

    def _send_smtp_alert(self, subject: str, body: str):
        cfg = self.alert_config["smtp"]
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = cfg["from"]
        msg["To"] = ", ".join(cfg["to"])
        msg.set_content(body)
        server = smtplib.SMTP(cfg["server"], cfg.get("port", 587), timeout=10)
        try:
            server.starttls()
            server.login(cfg["username"], cfg["password"])
            server.send_message(msg)
            self.logger.info("SMTP alert sent to %s", cfg["to"])
        finally:
            server.quit()

    def _send_slack_alert(self, text: str):
        url = self.alert_config["slack"]["webhook_url"]
        payload = {"text": f"Network anomaly detected:\n```{text}```"}
        resp = requests.post(url, json=payload, timeout=5)
        resp.raise_for_status()
        self.logger.info("Slack alert sent")

# === CLI / Run ===
def load_alert_config_from_file(path):
    if not path:
        return ALERT_CONFIG
    if os.path.exists(path):
        with open(path, "r") as f:
            cfg = json.load(f)
            return {**ALERT_CONFIG, **cfg}
    else:
        raise FileNotFoundError(path)


def main():
    parser = argparse.ArgumentParser(description="Network anomaly detector (live).")
    parser.add_argument("-i", "--iface", help="Network interface to sniff (default: first non-loopback)")
    parser.add_argument("-w", "--window", type=int, default=DEFAULT_WINDOW, help="sliding window seconds")
    parser.add_argument("-b", "--baseline", type=int, default=BASELINE_SECONDS,
                        help="seconds to collect baseline before detection")
    parser.add_argument("-t", "--threshold", type=float, default=ANOMALY_THRESHOLD,
                        help="anomaly threshold (IsolationForest score)")
    parser.add_argument("--alert-config", help="path to JSON alert config (SMTP / Slack)", default=None)
    parser.add_argument("--loglevel", default="INFO")
    args = parser.parse_args()

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    global LOG_LEVEL
    LOG_LEVEL = getattr(logging, args.loglevel.upper(), logging.INFO)

    alert_cfg = load_alert_config_from_file(args.alert_config)
    detector = NetAnomDetector(iface=args.iface, window=args.window,
                               baseline_seconds=args.baseline,
                               anomaly_threshold=args.threshold,
                               alert_config=alert_cfg)
    try:
        detector.start()
    except KeyboardInterrupt:
        print("Exiting...")

if __name__ == "__main__":
    main()
