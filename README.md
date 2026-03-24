# Proxy Firewall with ML Anomaly Detection

A sophisticated proxy firewall implemented in Python that combines traditional security mechanisms with machine learning-based anomaly detection. This project provides real-time traffic monitoring, intrusion detection, deep packet inspection (DPI), rate limiting, and an interactive web dashboard for comprehensive network security management.

## Features

### Core Security Features
- **HTTP/HTTPS Proxy**: Full proxy server supporting both HTTP and HTTPS traffic with CONNECT tunneling
- **Rate Limiting**: Configurable per-IP rate limits (default: 220 requests/minute)
- **Intrusion Detection System (IDS)**: Detects flood attacks (>60 requests/10s) and port scans (>25 distinct hosts/10s)
- **Deep Packet Inspection (DPI)**: Signature-based content filtering for malware, torrents, and SQL injection attempts
- **IP and Site Blocking**: Manual blocking of specific IPs and domains
- **Time-Based Rules**: Schedule-based blocking rules (e.g., block social media during work hours)
- **Stateful Connection Tracking**: Monitors active connections with detailed statistics

### Machine Learning Anomaly Detection
- **Isolation Forest Algorithm**: Unsupervised ML for detecting unusual traffic patterns
- **Real-time Feature Extraction**: Analyzes requests per IP, request frequency, packet size, and port usage
- **Automatic Severity Classification**: LOW/MEDIUM/HIGH severity based on anomaly scores
- **Auto-blocking**: Optional automatic IP blocking after repeated anomalies (configurable threshold: 3)

### Alert System
- **Multi-channel Alerts**: Console output, file logging (JSON), and optional email notifications
- **Persistent Storage**: Alerts stored in `alerts.json` with full feature context
- **Real-time Notifications**: Immediate alerts for critical security events

### Web Dashboard
- **Real-time Monitoring**: Live charts showing traffic trends and anomaly patterns
- **Interactive Controls**: Web interface for configuration and management
- **Comprehensive Statistics**: Request counts, anomaly metrics, blocked IPs, active connections
- **Alert and Log Viewer**: Real-time display of security events and traffic logs

### Advanced Features
- **Multithreaded Architecture**: Handles multiple concurrent connections efficiently
- **Thread-safe Operations**: All state modifications protected with threading locks
- **Rolling Time Windows**: Maintains 60-second and 10-second sliding windows for rate calculations
- **Traffic Series Aggregation**: Minute-by-minute traffic statistics with 180-minute history
- **Top Domain Tracking**: Monitors most accessed domains
- **Suspicious IP Monitoring**: Tracks IPs with anomaly history

## Technical Architecture

### Networking and Protocols
- **Socket Programming**: Uses Python's `socket` module for low-level TCP connections
- **HTTP Parsing**: Custom HTTP request parsing for CONNECT and standard HTTP methods
- **HTTPS Tunneling**: Establishes secure tunnels for encrypted traffic
- **Non-blocking I/O**: Uses `select()` for efficient multiplexing of multiple connections
- **Connection Pooling**: Maintains up to 256 concurrent connections

### Multithreading Design
- **Main Proxy Thread**: Single thread accepting new connections
- **Per-Client Threads**: Dedicated daemon threads for each client connection
- **Dashboard Thread**: Separate thread for Flask web server
- **Thread Synchronization**: `threading.Lock()` protects shared state (logs, alerts, counters)
- **Daemon Threads**: Automatic cleanup on main thread exit

### Machine Learning Implementation

#### Isolation Forest Details
The anomaly detection uses scikit-learn's `IsolationForest` with the following parameters:
- **n_estimators**: 60 trees (higher than default for better accuracy)
- **contamination**: 0.08 (expects 8% of traffic to be anomalous)
- **random_state**: 42 (for reproducible results)
- **n_jobs**: 1 (single-threaded to avoid GIL contention)

#### Feature Engineering
Four features are extracted for each request:
1. **requests_per_ip**: Total requests from IP in last 60 seconds (sliding window)
2. **request_frequency**: Requests per second in last 10 seconds
3. **packet_size**: Size of the HTTP request payload in bytes
4. **port_number**: Target port number (80, 443, etc.)

#### Training Dataset
The model is trained on synthetic "normal" traffic data:
- **Sample Size**: 300 training samples
- **Normal Traffic Simulation**:
  - Requests per IP: 1-40 (uniform distribution)
  - Request frequency: 0.05-2.5 requests/second
  - Packet size: 200-1800 bytes
  - Common ports: 80, 443, 8080 (web traffic focus)

#### Anomaly Scoring
- **Decision Function**: Returns anomaly score (-1 to 1, lower = more anomalous)
- **Heuristic Fallback**: Pure Python scoring when sklearn unavailable
- **Severity Mapping**:
  - HIGH: frequency ≥8 req/s OR requests_per_ip ≥160
  - MEDIUM: frequency ≥3 req/s OR requests_per_ip ≥70
  - LOW: All other cases

### Data Structures and Performance
- **Deques for Time Series**: O(1) append/pop operations for sliding windows
- **Defaultdicts**: Efficient sparse storage for per-IP tracking
- **Threading Locks**: Minimal lock contention with fine-grained locking
- **Memory Limits**: Configurable bounds (4000 logs, 400 alerts, 180 series points)

## Installation and Setup

### Prerequisites
- Python 3.8+
- pip package manager

### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/proxy-firewall.git
   cd proxy-firewall
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   ```

3. **Activate virtual environment**:
   - Windows:
     ```bash
     venv\Scripts\activate
     ```
   - Linux/Mac:
     ```bash
     source venv/bin/activate
     ```

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Dependencies Explained
- **Flask 3.0.3**: Web framework for the dashboard API
- **numpy 2.2.4**: Numerical computing for ML features
- **scikit-learn 1.6.1**: Machine learning library for Isolation Forest
- **proxy.py 2.4.10**: (Listed but not used in current implementation)

## Usage

### Starting the Firewall

1. **Basic startup**:
   ```bash
   python main.py
   ```

2. **Expected output**:
   ```
   [init] Starting Proxy Firewall with ML anomaly detection and dashboard
   [dashboard] http://127.0.0.1:5000
   [proxy] running on 127.0.0.1:8899
   ```

### Configuring Proxy in Browser/Client

- **HTTP Proxy**: `127.0.0.1:8899`
- **HTTPS**: The firewall handles CONNECT requests automatically
- **System-wide**: Configure in OS network settings or browser proxy settings

### Accessing the Dashboard

Open `http://127.0.0.1:5000` in your browser for the web interface.

## Configuration

### Default Settings
- **Proxy Host**: 127.0.0.1
- **Proxy Port**: 8899
- **Dashboard Host**: 127.0.0.1
- **Dashboard Port**: 5000
- **Rate Limit**: 220 requests/minute
- **Blocked Ports**: 21 (FTP), 25 (SMTP)
- **Blocked Sites**: youtube.com, facebook.com
- **DPI Signatures**: .exe, torrent, malware, EICAR test string

### Runtime Configuration
All settings can be modified via the web dashboard or API calls.

### Email Alerts (Optional)
To enable email notifications, modify `alert_system.py`:
```python
email_config = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "your-email@gmail.com",
    "sender_password": "your-app-password",
    "recipient_email": "alerts@yourdomain.com"
}
```

## API Endpoints

### Dashboard API
- `GET /api/summary` - System statistics
- `GET /api/logs?limit=100` - Recent traffic logs
- `GET /api/alerts?limit=100` - Security alerts
- `GET /api/stateful` - Active connections
- `GET /api/traffic/top-domains` - Most accessed domains
- `GET /api/traffic/series` - Traffic time series
- `GET /api/suspicious-ips` - IPs with anomalies
- `GET /api/config` - Current configuration

### Management API
- `POST /api/settings` - Update firewall settings
- `POST /api/blocked-ips` - Add blocked IP
- `DELETE /api/blocked-ips/{ip}` - Remove blocked IP
- `POST /api/block-sites` - Add blocked site
- `DELETE /api/block-sites/{site}` - Remove blocked site
- `POST /api/time-rules` - Add time-based rule
- `PATCH /api/time-rules/{id}/toggle` - Enable/disable time rule
- `DELETE /api/time-rules/{id}` - Delete time rule

## Blocking Mechanisms

### Automatic Blocking
1. **Rate Limiting**: Blocks IPs exceeding rate limit
2. **Anomaly Auto-block**: Blocks IPs after repeated anomalies (if enabled)
3. **Policy Violations**: Blocks based on port, IP, or site blacklists

### Manual Blocking
- **IP Blocking**: Add specific IPs via dashboard
- **Site Blocking**: Block entire domains
- **Time Rules**: Schedule-based blocking with keywords

### Deep Packet Inspection
Scans payload for:
- File extensions (.exe)
- Keywords (torrent, malware)
- SQL injection patterns (SELECT ... UNION)
- EICAR test virus signature

## Alert System Details

### Alert Categories
- **ANOMALY**: ML-detected unusual traffic
- **IDS**: Intrusion detection (floods, scans)
- **DPI**: Deep packet inspection matches
- **AUTO_BLOCK**: Automatic IP blocking events

### Alert Storage
- **File**: `alerts.json` with JSON array of alert objects
- **Memory**: Rolling deque with 400 max alerts
- **Format**: Timestamp, severity, IP, reason, features

### Notification Channels
1. **Console**: Immediate print to stdout
2. **Beep**: System beep sound (Windows)
3. **Email**: SMTP-based email alerts (configurable)
4. **File**: Persistent JSON logging

## Computer Networking Concepts

### TCP Connection Handling
- **Three-way Handshake**: Managed by OS socket layer
- **Connection States**: NEW → ESTABLISHED → CLOSED
- **Timeout Handling**: 8-second connect timeout, 2-second select timeout

### Proxy Architecture
- **Transparent Proxy**: Clients unaware of proxy presence
- **CONNECT Method**: HTTPS tunneling through HTTP CONNECT
- **Request Parsing**: Custom HTTP header parsing
- **Host Normalization**: Strips protocols, ports for domain matching

### Traffic Analysis
- **Sliding Windows**: Maintains time-based statistics
- **Feature Vectors**: ML-ready numerical features
- **Stateful Tracking**: Per-connection byte counters
- **Protocol Detection**: HTTP vs HTTPS classification

### Security Considerations
- **Input Validation**: Sanitizes all user inputs
- **Thread Safety**: Protects against race conditions
- **Memory Bounds**: Prevents unbounded growth
- **Graceful Degradation**: Works without ML dependencies

## Performance Characteristics

### Throughput
- **Concurrent Connections**: Up to 256 simultaneous clients
- **Request Processing**: Sub-millisecond per request
- **Memory Usage**: ~50MB baseline + per-connection overhead

### Scalability
- **Threading Model**: One thread per connection (CPU bound)
- **I/O Multiplexing**: Efficient select() for tunnel forwarding
- **Data Structures**: O(1) operations for common paths

### Limitations
- **Single Machine**: No distributed architecture
- **Memory Resident**: No persistent state across restarts
- **Python GIL**: Single-core ML inference

## Troubleshooting

### Common Issues
1. **Port Conflicts**: Change proxy/dashboard ports if 8899/5000 in use
2. **ML Not Working**: Ensure numpy/scikit-learn installed
3. **Dashboard Not Loading**: Check Flask installation and port availability
4. **No Alerts**: Verify IDS/DPI/anomaly detection enabled

### Logs and Debugging
- **Console Output**: Real-time status messages
- **Traffic Logs**: Detailed per-request logging
- **Alert History**: JSON file with full context
- **Connection Tracking**: Active session monitoring

## Development and Extension

### Code Structure
- `firewall.py`: Main controller and proxy logic
- `anomaly_detector.py`: ML anomaly detection wrapper
- `alert_system.py`: Alert handling and notifications
- `dashboard.py`: Flask web application
- `main.py`: Application entry point

### Adding New Features
- **Custom Signatures**: Extend DPI in `firewall.py`
- **New ML Models**: Implement in `anomaly_detector.py`
- **Alert Channels**: Extend `alert_system.py`
- **Dashboard Widgets**: Modify `dashboard_frontend.js`

### Testing
- **Unit Tests**: Test individual components
- **Integration Tests**: Full proxy testing with clients
- **Load Testing**: Concurrent connection handling
- **ML Validation**: Anomaly detection accuracy testing

## License

This project is open source. See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Security Notice

This is a research/educational implementation. For production use, consider:
- Professional security auditing
- Performance optimization
- Distributed deployment
- Advanced threat intelligence integration
- Regulatory compliance (GDPR, etc.)

---

**Built with Python, scikit-learn, Flask, and modern web technologies for comprehensive network security monitoring.**