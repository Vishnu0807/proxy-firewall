import select
import socket
import threading
import time
import uuid
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Deque, Dict, List, Optional, Set, Tuple

from alert_system import AlertSystem
from anomaly_detector import AnomalyDetector


PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8899
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5000


@dataclass
class ConnectionState:
    connection_id: str
    client_ip: str
    target_host: str
    target_port: int
    protocol: str
    state: str
    opened_at: float
    last_seen: float
    up: int = 0
    down: int = 0
    up_packets: int = 0
    down_packets: int = 0
    close_reason: str = ""


@dataclass
class TimeRule:
    rule_id: str
    keyword: str
    start_hour: int
    end_hour: int
    days: List[int]
    enabled: bool = True


class ProxyFirewall:
    """Main controller for proxy filtering, alerts, and dashboard APIs."""

    def __init__(self) -> None:
        self.proxy_host = PROXY_HOST
        self.proxy_port = PROXY_PORT
        self.dashboard_host = DASHBOARD_HOST
        self.dashboard_port = DASHBOARD_PORT

        self.rate_limit_per_minute = 220
        self.ids_enabled = True
        self.dpi_enabled = True
        self.anomaly_detection_enabled = True
        self.auto_block_enabled = False
        self.auto_block_threshold = 3

        self.blocked_ports: Set[int] = {21, 25}
        self.blocked_ips: Set[str] = set()
        self.blocked_sites: Set[str] = {"youtube.com", "facebook.com"}
        self.dpi_signatures = [
            b".exe",
            b"torrent",
            b"malware",
            b"x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar",
        ]

        self.max_logs = 4000
        self.max_alerts = 400
        self.state_lock = threading.Lock()

        self.logs: Deque[Dict] = deque(maxlen=self.max_logs)
        self.alerts: Deque[Dict] = deque(maxlen=self.max_alerts)
        self.connection_table: Dict[str, ConnectionState] = {}
        self.schedule_rules: Dict[str, TimeRule] = {}
        self.action_counter: Counter = Counter()
        self.host_counter: Counter = Counter()
        self.anomaly_counter: Counter = Counter()
        self.traffic_series: Deque[Dict] = deque(maxlen=180)
        self.last_series_key: Optional[str] = None

        self.client_rate_window: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=600))
        self.client_targets_window: Dict[str, Deque[Tuple[float, str]]] = defaultdict(lambda: deque(maxlen=800))
        self.last_alert_by_key: Dict[str, float] = defaultdict(float)

        self.anomaly_detector = AnomalyDetector()
        self.alert_system = AlertSystem(alerts_path="alerts.json")

    def now_str(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def normalize_domain(value: str) -> str:
        domain = value.strip().lower()
        domain = domain.removeprefix("http://").removeprefix("https://")
        domain = domain.split("/")[0]
        if ":" in domain:
            domain = domain.split(":")[0]
        return domain

    def push_alert(
        self,
        category: str,
        message: str,
        client_ip: str = "",
        severity: str = "LOW",
        reason: str = "",
        features: Optional[Dict] = None,
    ) -> Dict:
        alert = {
            "time": self.now_str(),
            "category": category,
            "message": message,
            "client_ip": client_ip,
            "severity": severity,
            "reason": reason or message,
            "features": features or {},
        }
        with self.state_lock:
            self.alerts.appendleft(alert)
        return alert

    def push_log(
        self,
        client_ip: str,
        host: str,
        port: int,
        protocol: str,
        action: str,
        reason: str = "",
        up: int = 0,
        down: int = 0,
    ) -> None:
        with self.state_lock:
            self.logs.appendleft(
                {
                    "time": self.now_str(),
                    "client_ip": client_ip,
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "action": action,
                    "reason": reason,
                    "up": up,
                    "down": down,
                }
            )
            self.action_counter[action] += 1

    def roll_series(self, action: str, up: int, down: int, anomaly_count: int = 0) -> None:
        key = datetime.now().strftime("%H:%M")
        with self.state_lock:
            if key != self.last_series_key:
                self.traffic_series.append(
                    {
                        "minute": key,
                        "allowed": 0,
                        "blocked": 0,
                        "anomalies": 0,
                        "up": 0,
                        "down": 0,
                    }
                )
                self.last_series_key = key
            bucket = self.traffic_series[-1]
            if action == "ALLOWED":
                bucket["allowed"] += 1
            else:
                bucket["blocked"] += 1
            bucket["anomalies"] += anomaly_count
            bucket["up"] += up
            bucket["down"] += down

    def register_request(self, client_ip: str) -> Tuple[int, float]:
        # Keep a rolling time window per IP so we can calculate both
        # requests-per-minute and requests-per-second style features.
        now = time.time()
        start_60 = now - 60
        start_10 = now - 10
        with self.state_lock:
            window = self.client_rate_window[client_ip]
            window.append(now)
            while window and window[0] < start_60:
                window.popleft()
            recent_count = sum(1 for ts in window if ts >= start_10)
            request_count = len(window)
        request_frequency = round(recent_count / 10, 2)
        return request_count, request_frequency

    def is_rate_limited(self, request_count: int) -> bool:
        return request_count > self.rate_limit_per_minute

    def detect_intrusion(self, client_ip: str, host: str) -> None:
        if not self.ids_enabled:
            return

        now = time.time()
        start = now - 10
        with self.state_lock:
            window = self.client_targets_window[client_ip]
            window.append((now, host))
            while window and window[0][0] < start:
                window.popleft()
            request_count = len(window)
            distinct_hosts = len({entry_host for _, entry_host in window})

        flood_key = f"{client_ip}:flood"
        if request_count > 60 and now - self.last_alert_by_key[flood_key] > 20:
            self.last_alert_by_key[flood_key] = now
            self.push_alert(
                "IDS",
                f"Possible flood from {client_ip}: {request_count} requests in 10 seconds",
                client_ip=client_ip,
                severity="HIGH",
            )

        scan_key = f"{client_ip}:scan"
        if distinct_hosts > 25 and now - self.last_alert_by_key[scan_key] > 20:
            self.last_alert_by_key[scan_key] = now
            self.push_alert(
                "IDS",
                f"Possible scan from {client_ip}: {distinct_hosts} targets in 10 seconds",
                client_ip=client_ip,
                severity="MEDIUM",
            )

    def dpi_match(self, payload: bytes) -> Optional[str]:
        if not self.dpi_enabled or not payload:
            return None

        lowered_payload = payload.lower()
        for signature in self.dpi_signatures:
            if signature in lowered_payload:
                return f"DPI matched signature: {signature.decode(errors='ignore')}"
        if b"select " in lowered_payload and b" union " in lowered_payload:
            return "DPI suspicious SQL injection sequence"
        return None

    def time_rule_hit(self, host: str) -> Optional[str]:
        now = datetime.now()
        current_day = now.weekday()
        current_hour = now.hour

        with self.state_lock:
            rules = list(self.schedule_rules.values())

        for rule in rules:
            if not rule.enabled or rule.keyword not in host or current_day not in rule.days:
                continue

            if rule.start_hour < rule.end_hour:
                in_window = rule.start_hour <= current_hour < rule.end_hour
            else:
                in_window = current_hour >= rule.start_hour or current_hour < rule.end_hour

            if in_window:
                return f"Time rule ({rule.keyword} {rule.start_hour:02d}-{rule.end_hour:02d})"
        return None

    def parse_target(self, data: bytes) -> Tuple[str, int, str, bytes]:
        lines = data.split(b"\r\n")
        if not lines or len(lines[0].split()) < 2:
            raise ValueError("Bad request line")

        method = lines[0].split()[0].decode(errors="ignore").upper()
        if method == "CONNECT":
            hostport = lines[0].split()[1].decode(errors="ignore")
            host, port = hostport.rsplit(":", 1)
            return self.normalize_domain(host), int(port), "HTTPS", b""

        host_header = ""
        for line in lines[1:]:
            if line.lower().startswith(b"host:"):
                host_header = line.split(b":", 1)[1].strip().decode(errors="ignore")
                break

        if not host_header:
            raise ValueError("Missing Host header")

        if ":" in host_header:
            host, port = host_header.rsplit(":", 1)
            return self.normalize_domain(host), int(port), "HTTP", data

        return self.normalize_domain(host_header), 80, "HTTP", data

    def policy_decision(self, client_ip: str, host: str, port: int) -> Optional[str]:
        if client_ip in self.blocked_ips:
            return "Blocked source IP"
        if port in self.blocked_ports:
            return f"Blocked destination port {port}"
        if any(site in host for site in self.blocked_sites):
            return "Blocked by site policy"

        time_rule_reason = self.time_rule_hit(host)
        if time_rule_reason:
            return time_rule_reason
        return None

    def build_features(self, client_ip: str, port: int, request_size: int) -> Dict:
        # These are the exact features requested for the ML detector.
        requests_per_ip, request_frequency = self.register_request(client_ip)
        return {
            "requests_per_ip": requests_per_ip,
            "request_frequency": request_frequency,
            "packet_size": int(request_size),
            "port_number": int(port),
        }

    def handle_anomaly(self, client_ip: str, features: Dict) -> bool:
        if not self.anomaly_detection_enabled:
            return False

        if self.anomaly_detector.detect_anomaly(features) != "ANOMALY":
            return False

        severity = self.alert_system.calculate_severity(features)
        alert = self.alert_system.trigger_alert(
            ip=client_ip,
            features=features,
            severity=severity,
            reason="Isolation Forest flagged traffic as unusual",
        )
        with self.state_lock:
            self.alerts.appendleft(alert)
            self.anomaly_counter[client_ip] += 1
            repeat_count = self.anomaly_counter[client_ip]

        if self.auto_block_enabled and repeat_count >= self.auto_block_threshold:
            with self.state_lock:
                self.blocked_ips.add(client_ip)
            self.push_alert(
                "AUTO_BLOCK",
                f"IP {client_ip} was blocked after repeated anomalies",
                client_ip=client_ip,
                severity="HIGH",
                reason="Repeated anomaly detections",
                features=features,
            )

        return True

    def tunnel(self, conn_id: str, client: socket.socket, remote: socket.socket) -> Tuple[int, int]:
        sockets = [client, remote]
        upload_bytes = 0
        download_bytes = 0

        while True:
            ready, _, _ = select.select(sockets, [], [], 2)
            if not ready:
                with self.state_lock:
                    connection = self.connection_table.get(conn_id)
                    if connection:
                        connection.last_seen = time.time()
                continue

            for source_socket in ready:
                chunk = source_socket.recv(8192)
                if not chunk:
                    return upload_bytes, download_bytes

                dpi_result = self.dpi_match(chunk)
                if dpi_result:
                    self.push_alert("DPI", dpi_result, severity="MEDIUM")
                    return upload_bytes, download_bytes

                if source_socket is client:
                    remote.sendall(chunk)
                    upload_bytes += len(chunk)
                    with self.state_lock:
                        connection = self.connection_table.get(conn_id)
                        if connection:
                            connection.up += len(chunk)
                            connection.up_packets += 1
                            connection.last_seen = time.time()
                else:
                    client.sendall(chunk)
                    download_bytes += len(chunk)
                    with self.state_lock:
                        connection = self.connection_table.get(conn_id)
                        if connection:
                            connection.down += len(chunk)
                            connection.down_packets += 1
                            connection.last_seen = time.time()

    def handle_client(self, client: socket.socket, addr: Tuple[str, int]) -> None:
        client_ip = addr[0]
        connection_id = str(uuid.uuid4())[:8]
        remote: Optional[socket.socket] = None
        anomaly_detected = False

        try:
            request_bytes = client.recv(8192)
            if not request_bytes:
                return

            host, port, protocol, payload = self.parse_target(request_bytes)
            self.detect_intrusion(client_ip, host)

            # Extract traffic features before we apply policy decisions so the
            # detector sees the incoming request pattern in real time.
            features = self.build_features(client_ip, port, len(request_bytes))
            anomaly_detected = self.handle_anomaly(client_ip, features)

            if self.is_rate_limited(features["requests_per_ip"]):
                severity = self.alert_system.calculate_severity(features)
                rate_alert = self.alert_system.trigger_alert(
                    ip=client_ip,
                    features=features,
                    severity=severity,
                    reason="Rate limit exceeded",
                )
                with self.state_lock:
                    self.alerts.appendleft(rate_alert)
                self.push_log(client_ip, host, port, protocol, "BLOCKED", "Rate limit exceeded")
                self.roll_series("BLOCKED", 0, 0, anomaly_count=1 if anomaly_detected else 0)
                return

            policy_reason = self.policy_decision(client_ip, host, port)
            if policy_reason:
                self.push_log(client_ip, host, port, protocol, "BLOCKED", policy_reason)
                self.roll_series("BLOCKED", 0, 0, anomaly_count=1 if anomaly_detected else 0)
                return

            opened_at = time.time()
            with self.state_lock:
                self.connection_table[connection_id] = ConnectionState(
                    connection_id=connection_id,
                    client_ip=client_ip,
                    target_host=host,
                    target_port=port,
                    protocol=protocol,
                    state="NEW",
                    opened_at=opened_at,
                    last_seen=opened_at,
                )

            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(8)
            remote.connect((host, port))
            remote.settimeout(None)

            with self.state_lock:
                self.connection_table[connection_id].state = "ESTABLISHED"

            if protocol == "HTTPS":
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            elif payload:
                remote.sendall(payload)

            upload_bytes, download_bytes = self.tunnel(connection_id, client, remote)
            self.push_log(
                client_ip,
                host,
                port,
                protocol,
                "ALLOWED",
                up=upload_bytes,
                down=download_bytes,
            )
            self.roll_series(
                "ALLOWED",
                upload_bytes,
                download_bytes,
                anomaly_count=1 if anomaly_detected else 0,
            )
            with self.state_lock:
                self.host_counter[host] += 1
        except Exception as exc:  # noqa: BLE001
            self.push_log(client_ip, "-", 0, "N/A", "BLOCKED", str(exc))
            self.roll_series("BLOCKED", 0, 0, anomaly_count=1 if anomaly_detected else 0)
        finally:
            with self.state_lock:
                connection = self.connection_table.get(connection_id)
                if connection:
                    connection.state = "CLOSED"
                    connection.last_seen = time.time()
            try:
                client.close()
            except OSError:
                pass
            if remote:
                try:
                    remote.close()
                except OSError:
                    pass

    def start_proxy(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.proxy_host, self.proxy_port))
        server.listen(256)
        print(f"[proxy] running on {self.proxy_host}:{self.proxy_port}")

        while True:
            client, addr = server.accept()
            threading.Thread(target=self.handle_client, args=(client, addr), daemon=True).start()

    def seed_defaults(self) -> None:
        default_rule = TimeRule(
            rule_id=str(uuid.uuid4())[:8],
            keyword="social",
            start_hour=9,
            end_hour=17,
            days=[0, 1, 2, 3, 4],
            enabled=False,
        )
        with self.state_lock:
            self.schedule_rules[default_rule.rule_id] = default_rule

    def get_summary(self) -> Dict:
        with self.state_lock:
            total = sum(self.action_counter.values())
            open_connections = sum(
                1 for item in self.connection_table.values() if item.state in {"NEW", "ESTABLISHED"}
            )
            return {
                "total_requests": total,
                "allowed": self.action_counter.get("ALLOWED", 0),
                "blocked": self.action_counter.get("BLOCKED", 0),
                "total_anomalies": sum(self.anomaly_counter.values()),
                "blocked_ips": len(self.blocked_ips),
                "open_connections": open_connections,
                "rate_limit": self.rate_limit_per_minute,
                "ids_enabled": self.ids_enabled,
                "dpi_enabled": self.dpi_enabled,
                "anomaly_detection_enabled": self.anomaly_detection_enabled,
                "auto_block_enabled": self.auto_block_enabled,
            }

    def get_logs(self, limit: int = 100) -> List[Dict]:
        with self.state_lock:
            return list(self.logs)[:limit]

    def get_alerts(self, limit: int = 100) -> List[Dict]:
        with self.state_lock:
            return list(self.alerts)[:limit]

    def get_stateful_connections(self, limit: int = 120) -> List[Dict]:
        with self.state_lock:
            rows = sorted(self.connection_table.values(), key=lambda item: item.last_seen, reverse=True)[:limit]

        result = []
        for row in rows:
            row_dict = asdict(row)
            row_dict["last_seen_human"] = datetime.fromtimestamp(row.last_seen).strftime("%H:%M:%S")
            result.append(row_dict)
        return result

    def get_top_domains(self, limit: int = 10) -> List[Dict]:
        with self.state_lock:
            return [{"host": host, "count": count} for host, count in self.host_counter.most_common(limit)]

    def get_traffic_series(self) -> List[Dict]:
        with self.state_lock:
            return list(self.traffic_series)

    def get_suspicious_ips(self, limit: int = 20) -> List[Dict]:
        with self.state_lock:
            items = self.anomaly_counter.most_common(limit)
            return [
                {
                    "ip": ip,
                    "anomalies": count,
                    "blocked": ip in self.blocked_ips,
                }
                for ip, count in items
            ]

    def get_config(self) -> Dict:
        with self.state_lock:
            return {
                "rate_limit": self.rate_limit_per_minute,
                "ids_enabled": self.ids_enabled,
                "dpi_enabled": self.dpi_enabled,
                "anomaly_detection_enabled": self.anomaly_detection_enabled,
                "auto_block_enabled": self.auto_block_enabled,
                "blocked_ips": sorted(self.blocked_ips),
                "blocked_sites": sorted(self.blocked_sites),
                "time_rules": [asdict(rule) for rule in self.schedule_rules.values()],
            }

    def update_settings(self, payload: Dict) -> Dict:
        if "rate_limit" in payload:
            rate_limit = int(payload["rate_limit"])
            if rate_limit < 10 or rate_limit > 5000:
                raise ValueError("rate_limit must be between 10 and 5000")
            self.rate_limit_per_minute = rate_limit
        if isinstance(payload.get("ids_enabled"), bool):
            self.ids_enabled = payload["ids_enabled"]
        if isinstance(payload.get("dpi_enabled"), bool):
            self.dpi_enabled = payload["dpi_enabled"]
        if isinstance(payload.get("anomaly_detection_enabled"), bool):
            self.anomaly_detection_enabled = payload["anomaly_detection_enabled"]
        if isinstance(payload.get("auto_block_enabled"), bool):
            self.auto_block_enabled = payload["auto_block_enabled"]
        return self.get_config()

    def add_blocked_ip(self, ip: str) -> str:
        if not ip:
            raise ValueError("ip is required")
        with self.state_lock:
            self.blocked_ips.add(ip)
        return ip

    def remove_blocked_ip(self, ip: str) -> None:
        with self.state_lock:
            self.blocked_ips.discard(ip)

    def add_blocked_site(self, site: str) -> str:
        normalized_site = self.normalize_domain(site)
        if not normalized_site:
            raise ValueError("site is required")
        with self.state_lock:
            self.blocked_sites.add(normalized_site)
        return normalized_site

    def remove_blocked_site(self, site: str) -> None:
        with self.state_lock:
            self.blocked_sites.discard(self.normalize_domain(site))

    def add_time_rule(self, payload: Dict) -> Dict:
        keyword = self.normalize_domain(payload.get("keyword", ""))
        if not keyword:
            raise ValueError("keyword is required")

        start_hour = int(payload.get("start_hour"))
        end_hour = int(payload.get("end_hour"))
        if not (0 <= start_hour <= 23 and 0 <= end_hour <= 23):
            raise ValueError("hours must be in range 0..23")

        day_values = payload.get("days", [])
        if not isinstance(day_values, list) or not day_values:
            raise ValueError("days must be a non-empty list")

        days = sorted({int(day) for day in day_values})
        if any(day < 0 or day > 6 for day in days):
            raise ValueError("days values must be in range 0..6")

        rule = TimeRule(
            rule_id=str(uuid.uuid4())[:8],
            keyword=keyword,
            start_hour=start_hour,
            end_hour=end_hour,
            days=days,
            enabled=True,
        )
        with self.state_lock:
            self.schedule_rules[rule.rule_id] = rule
        return asdict(rule)

    def toggle_time_rule(self, rule_id: str) -> Dict:
        with self.state_lock:
            rule = self.schedule_rules.get(rule_id)
            if not rule:
                raise KeyError("rule not found")
            rule.enabled = not rule.enabled
            return asdict(rule)

    def delete_time_rule(self, rule_id: str) -> None:
        with self.state_lock:
            if rule_id not in self.schedule_rules:
                raise KeyError("rule not found")
            del self.schedule_rules[rule_id]


def main() -> None:
    from dashboard import start_dashboard

    firewall = ProxyFirewall()
    firewall.seed_defaults()
    print("[init] Starting Proxy Firewall with ML anomaly detection and dashboard")
    threading.Thread(
        target=start_dashboard,
        args=(firewall,),
        kwargs={"host": firewall.dashboard_host, "port": firewall.dashboard_port},
        daemon=True,
    ).start()
    firewall.start_proxy()


if __name__ == "__main__":
    main()
