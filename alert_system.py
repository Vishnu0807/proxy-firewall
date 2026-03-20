import json
import os
import smtplib
import threading
from datetime import datetime
from email.message import EmailMessage
from typing import Dict, List, Optional


class AlertSystem:
    """Handles console, file, sound, and optional email alerts."""

    def __init__(self, alerts_path: str = "alerts.json", email_config: Optional[Dict] = None) -> None:
        self.alerts_path = alerts_path
        self.email_config = email_config or {}
        self._file_lock = threading.Lock()
        self._ensure_alert_file()

    def _ensure_alert_file(self) -> None:
        if os.path.exists(self.alerts_path):
            return
        with open(self.alerts_path, "w", encoding="utf-8") as file_handle:
            json.dump([], file_handle, indent=2)

    def _timestamp(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def calculate_severity(self, features: Dict) -> str:
        request_frequency = float(features.get("request_frequency", 0))
        requests_per_ip = int(features.get("requests_per_ip", 0))

        if request_frequency >= 8 or requests_per_ip >= 160:
            return "HIGH"
        if request_frequency >= 3 or requests_per_ip >= 70:
            return "MEDIUM"
        return "LOW"

    def _console_alert(self, ip: str, timestamp: str) -> None:
        print(f"[ALERT] Suspicious activity detected from IP {ip} at {timestamp}")

    def _beep(self) -> None:
        try:
            import winsound

            winsound.Beep(1200, 250)
            return
        except Exception:
            pass
        print("\a", end="", flush=True)

    def _read_alerts(self) -> List[Dict]:
        try:
            with open(self.alerts_path, "r", encoding="utf-8") as file_handle:
                return json.load(file_handle)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _write_alerts(self, alerts: List[Dict]) -> None:
        with open(self.alerts_path, "w", encoding="utf-8") as file_handle:
            json.dump(alerts, file_handle, indent=2)

    def _log_alert(self, alert: Dict) -> None:
        with self._file_lock:
            alerts = self._read_alerts()
            alerts.append(alert)
            self._write_alerts(alerts)

    def send_email_alert(self, message: str) -> bool:
        if not self.email_config:
            return False

        required_fields = {"smtp_server", "smtp_port", "sender_email", "sender_password", "recipient_email"}
        if not required_fields.issubset(self.email_config):
            return False

        email_message = EmailMessage()
        email_message["Subject"] = "Proxy Firewall Alert"
        email_message["From"] = self.email_config["sender_email"]
        email_message["To"] = self.email_config["recipient_email"]
        email_message.set_content(message)

        try:
            with smtplib.SMTP(self.email_config["smtp_server"], int(self.email_config["smtp_port"])) as smtp_server:
                smtp_server.starttls()
                smtp_server.login(
                    self.email_config["sender_email"],
                    self.email_config["sender_password"],
                )
                smtp_server.send_message(email_message)
            return True
        except Exception as exc:  # noqa: BLE001
            print(f"[alert-email] Failed to send email: {exc}")
            return False

    def trigger_alert(self, ip: str, features: Dict, severity: str, reason: str) -> Dict:
        timestamp = self._timestamp()
        alert = {
            "time": timestamp,
            "timestamp": timestamp,
            "ip": ip,
            "client_ip": ip,
            "category": "ANOMALY",
            "severity": severity,
            "reason": reason,
            "message": f"{severity} anomaly detected for {ip}",
            "features": {
                "requests_per_ip": features.get("requests_per_ip", 0),
                "request_frequency": features.get("request_frequency", 0),
                "packet_size": features.get("packet_size", 0),
                "port_number": features.get("port_number", 0),
            },
        }

        self._console_alert(ip, timestamp)
        self._log_alert(alert)
        self._beep()
        self.send_email_alert(json.dumps(alert, indent=2))
        return alert
