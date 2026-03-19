import select
import socket
import threading
import time
import uuid
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Deque, Dict, List, Optional, Set, Tuple

from flask import Flask, jsonify, render_template_string, request

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8899
DASHBOARD_PORT = 5000

RATE_LIMIT_PER_MINUTE = 220
IDS_ENABLED = True
DPI_ENABLED = True
BLOCKED_PORTS: Set[int] = {21, 25}
BLOCKED_IPS: Set[str] = set()
BLOCKED_SITES: Set[str] = {"youtube.com", "facebook.com"}

DPI_SIGNATURES = [b".exe", b"torrent", b"malware", b"x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar"]
MAX_LOGS = 4000
MAX_ALERTS = 400

state_lock = threading.Lock()


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


logs: Deque[Dict] = deque(maxlen=MAX_LOGS)
alerts: Deque[Dict] = deque(maxlen=MAX_ALERTS)
connection_table: Dict[str, ConnectionState] = {}
schedule_rules: Dict[str, TimeRule] = {}

action_counter: Counter = Counter()
host_counter: Counter = Counter()
traffic_series: Deque[Dict] = deque(maxlen=180)
last_series_key: Optional[str] = None

client_rate_window: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=500))
client_targets_window: Dict[str, Deque[Tuple[float, str]]] = defaultdict(lambda: deque(maxlen=800))
last_alert_by_key: Dict[str, float] = defaultdict(float)


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_domain(value: str) -> str:
    d = value.strip().lower()
    d = d.removeprefix("http://").removeprefix("https://")
    d = d.split("/")[0]
    if ":" in d:
        d = d.split(":")[0]
    return d


def push_alert(category: str, message: str, client_ip: str = "") -> None:
    with state_lock:
        alerts.appendleft({"time": now_str(), "category": category, "message": message, "client_ip": client_ip})


def push_log(
    client_ip: str,
    host: str,
    port: int,
    protocol: str,
    action: str,
    reason: str = "",
    up: int = 0,
    down: int = 0,
) -> None:
    with state_lock:
        logs.appendleft(
            {
                "time": now_str(),
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
        action_counter[action] += 1


def roll_series(action: str, up: int, down: int) -> None:
    global last_series_key
    key = datetime.now().strftime("%H:%M")
    with state_lock:
        if key != last_series_key:
            traffic_series.append({"minute": key, "allowed": 0, "blocked": 0, "up": 0, "down": 0})
            last_series_key = key
        bucket = traffic_series[-1]
        if action == "ALLOWED":
            bucket["allowed"] += 1
        else:
            bucket["blocked"] += 1
        bucket["up"] += up
        bucket["down"] += down


def is_rate_limited(client_ip: str) -> bool:
    now = time.time()
    start = now - 60
    with state_lock:
        dq = client_rate_window[client_ip]
        while dq and dq[0] < start:
            dq.popleft()
        if len(dq) >= RATE_LIMIT_PER_MINUTE:
            return True
        dq.append(now)
    return False


def detect_intrusion(client_ip: str, host: str) -> None:
    if not IDS_ENABLED:
        return
    now = time.time()
    start = now - 10
    with state_lock:
        dq = client_targets_window[client_ip]
        dq.append((now, host))
        while dq and dq[0][0] < start:
            dq.popleft()
        req_count = len(dq)
        distinct = len({h for _, h in dq})

    flood_key = f"{client_ip}:flood"
    if req_count > 60 and now - last_alert_by_key[flood_key] > 20:
        last_alert_by_key[flood_key] = now
        push_alert("IDS", f"Possible flood from {client_ip}: {req_count} req/10s", client_ip)

    scan_key = f"{client_ip}:scan"
    if distinct > 25 and now - last_alert_by_key[scan_key] > 20:
        last_alert_by_key[scan_key] = now
        push_alert("IDS", f"Possible scan from {client_ip}: {distinct} targets/10s", client_ip)


def dpi_match(payload: bytes) -> Optional[str]:
    if not DPI_ENABLED or not payload:
        return None
    low = payload.lower()
    for sig in DPI_SIGNATURES:
        if sig in low:
            return f"DPI matched signature: {sig.decode(errors='ignore')}"
    if b"select " in low and b" union " in low:
        return "DPI suspicious SQL injection sequence"
    return None


def time_rule_hit(host: str) -> Optional[str]:
    now = datetime.now()
    day, hour = now.weekday(), now.hour
    with state_lock:
        rules = list(schedule_rules.values())
    for r in rules:
        if not r.enabled or r.keyword not in host or day not in r.days:
            continue
        in_window = (r.start_hour <= hour < r.end_hour) if r.start_hour < r.end_hour else (hour >= r.start_hour or hour < r.end_hour)
        if in_window:
            return f"Time rule ({r.keyword} {r.start_hour:02d}-{r.end_hour:02d})"
    return None


def parse_target(data: bytes) -> Tuple[str, int, str, bytes]:
    lines = data.split(b"\r\n")
    if not lines or len(lines[0].split()) < 2:
        raise ValueError("Bad request line")
    method = lines[0].split()[0].decode(errors="ignore").upper()
    if method == "CONNECT":
        hostport = lines[0].split()[1].decode(errors="ignore")
        host, port = hostport.rsplit(":", 1)
        return normalize_domain(host), int(port), "HTTPS", b""
    host_header = ""
    for line in lines[1:]:
        if line.lower().startswith(b"host:"):
            host_header = line.split(b":", 1)[1].strip().decode(errors="ignore")
            break
    if not host_header:
        raise ValueError("Missing Host header")
    if ":" in host_header:
        host, port = host_header.rsplit(":", 1)
        return normalize_domain(host), int(port), "HTTP", data
    return normalize_domain(host_header), 80, "HTTP", data


def policy_decision(client_ip: str, host: str, port: int) -> Optional[str]:
    if client_ip in BLOCKED_IPS:
        return "Blocked source IP"
    if port in BLOCKED_PORTS:
        return f"Blocked destination port {port}"
    if any(x in host for x in BLOCKED_SITES):
        return "Blocked by site policy"
    tr = time_rule_hit(host)
    if tr:
        return tr
    return None


def tunnel(conn_id: str, client: socket.socket, remote: socket.socket) -> Tuple[int, int]:
    sockets = [client, remote]
    up = 0
    down = 0
    while True:
        ready, _, _ = select.select(sockets, [], [], 2)
        if not ready:
            with state_lock:
                c = connection_table.get(conn_id)
                if c:
                    c.last_seen = time.time()
            continue
        for sock_obj in ready:
            chunk = sock_obj.recv(8192)
            if not chunk:
                return up, down
            hit = dpi_match(chunk)
            if hit:
                push_alert("DPI", hit)
                return up, down
            if sock_obj is client:
                remote.sendall(chunk)
                up += len(chunk)
                with state_lock:
                    c = connection_table.get(conn_id)
                    if c:
                        c.up += len(chunk)
                        c.up_packets += 1
                        c.last_seen = time.time()
            else:
                client.sendall(chunk)
                down += len(chunk)
                with state_lock:
                    c = connection_table.get(conn_id)
                    if c:
                        c.down += len(chunk)
                        c.down_packets += 1
                        c.last_seen = time.time()


def handle_client(client: socket.socket, addr: Tuple[str, int]) -> None:
    client_ip = addr[0]
    conn_id = str(uuid.uuid4())[:8]
    remote = None
    try:
        if is_rate_limited(client_ip):
            push_log(client_ip, "-", 0, "N/A", "BLOCKED", "Rate limit exceeded")
            roll_series("BLOCKED", 0, 0)
            return

        req = client.recv(8192)
        if not req:
            return
        host, port, protocol, payload = parse_target(req)
        detect_intrusion(client_ip, host)

        reason = policy_decision(client_ip, host, port)
        if reason:
            push_log(client_ip, host, port, protocol, "BLOCKED", reason)
            roll_series("BLOCKED", 0, 0)
            return

        t = time.time()
        with state_lock:
            connection_table[conn_id] = ConnectionState(conn_id, client_ip, host, port, protocol, "NEW", t, t)

        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.settimeout(8)
        remote.connect((host, port))
        remote.settimeout(None)
        with state_lock:
            connection_table[conn_id].state = "ESTABLISHED"

        if protocol == "HTTPS":
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        elif payload:
            remote.sendall(payload)

        up, down = tunnel(conn_id, client, remote)
        push_log(client_ip, host, port, protocol, "ALLOWED", up=up, down=down)
        roll_series("ALLOWED", up, down)
        with state_lock:
            host_counter[host] += 1
    except Exception as exc:  # noqa: BLE001
        push_log(client_ip, "-", 0, "N/A", "BLOCKED", str(exc))
        roll_series("BLOCKED", 0, 0)
    finally:
        with state_lock:
            c = connection_table.get(conn_id)
            if c:
                c.state = "CLOSED"
                c.last_seen = time.time()
        try:
            client.close()
        except OSError:
            pass
        if remote:
            try:
                remote.close()
            except OSError:
                pass


def start_proxy() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((PROXY_HOST, PROXY_PORT))
    srv.listen(256)
    print(f"[proxy] running on {PROXY_HOST}:{PROXY_PORT}")
    while True:
        c, addr = srv.accept()
        threading.Thread(target=handle_client, args=(c, addr), daemon=True).start()


app = Flask(__name__)


HTML = """
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Firewall Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<style>
body{font-family:Segoe UI,Trebuchet MS,sans-serif;background:#0d1b2a;color:#eaf4ff;margin:0;padding:18px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(180px,1fr));gap:10px}.card{background:#1b263b;border:1px solid #3b4d6b;border-radius:10px;padding:10px}
.row{display:grid;grid-template-columns:2fr 1fr;gap:10px;margin-top:10px}.row2{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px}
input,select,button{width:100%;padding:8px;border-radius:8px;border:1px solid #466387;background:#10213a;color:#eaf4ff} button{cursor:pointer;background:#0077b6;border:none}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{border-bottom:1px solid #334862;padding:6px;text-align:left}th{color:#90e0ef}
.t{max-height:250px;overflow:auto}.chips{display:flex;flex-wrap:wrap;gap:6px}.chip{background:#10213a;border:1px solid #466387;border-radius:999px;padding:5px 8px}
@media(max-width:1000px){.grid{grid-template-columns:repeat(2,minmax(130px,1fr))}.row,.row2{grid-template-columns:1fr}}
</style></head><body>
<h2>Proxy Firewall SOC Dashboard</h2>
<div class="grid">
<div class="card"><div>Total</div><h3 id="mTotal">0</h3></div>
<div class="card"><div>Allowed</div><h3 id="mAllowed">0</h3></div>
<div class="card"><div>Blocked</div><h3 id="mBlocked">0</h3></div>
<div class="card"><div>Open Sessions</div><h3 id="mOpen">0</h3></div>
</div>
<div class="row">
<div class="card"><h3>Traffic Timeline</h3><canvas id="c1"></canvas></div>
<div class="card"><h3>Top Domains</h3><canvas id="c2"></canvas></div>
</div>
<div class="row2">
<div class="card"><h3>Block Sites</h3><form id="fSite"><input id="site" placeholder="example.com"><div style="height:8px"></div><button>Add</button></form><div id="sites" class="chips" style="margin-top:8px"></div></div>
<div class="card"><h3>Settings</h3><form id="fSet"><label>Rate Limit / min</label><input type="number" id="rate" min="10" max="5000"><label><input type="checkbox" id="ids" style="width:auto"> IDS</label><label><input type="checkbox" id="dpi" style="width:auto"> DPI</label><button>Save</button></form></div>
</div>
<div class="row2">
<div class="card"><h3>Time-based Rule</h3><form id="fRule"><input id="rk" placeholder="keyword/domain"><div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px"><input id="rs" type="number" min="0" max="23" value="9"><input id="re" type="number" min="0" max="23" value="17"></div><select id="rd" multiple size="7" style="margin-top:8px"><option value="0" selected>Mon</option><option value="1" selected>Tue</option><option value="2" selected>Wed</option><option value="3" selected>Thu</option><option value="4" selected>Fri</option><option value="5">Sat</option><option value="6">Sun</option></select><button style="margin-top:8px">Add Rule</button></form></div>
<div class="card"><h3>Active Rules</h3><div class="t"><table><thead><tr><th>Key</th><th>Window</th><th>Days</th><th>State</th><th>Action</th></tr></thead><tbody id="rules"></tbody></table></div></div>
</div>
<div class="card" style="margin-top:10px"><h3>Alerts</h3><div class="t"><table><thead><tr><th>Time</th><th>Type</th><th>Client</th><th>Message</th></tr></thead><tbody id="alerts"></tbody></table></div></div>
<div class="card" style="margin-top:10px"><h3>Stateful Table</h3><div class="t"><table><thead><tr><th>ID</th><th>Client</th><th>Target</th><th>Proto</th><th>State</th><th>Up</th><th>Down</th><th>Last</th></tr></thead><tbody id="state"></tbody></table></div></div>
<div class="card" style="margin-top:10px"><h3>Logs</h3><div class="t"><table><thead><tr><th>Time</th><th>Client</th><th>Host</th><th>Port</th><th>P</th><th>Action</th><th>Reason</th><th>Up</th><th>Down</th></tr></thead><tbody id="logs"></tbody></table></div></div>
<script>
const c1 = new Chart(document.getElementById('c1'),{type:'line',data:{labels:[],datasets:[{label:'Allowed',data:[],borderColor:'#27ae60'},{label:'Blocked',data:[],borderColor:'#e63946'},{label:'UpKB',data:[],borderColor:'#00b4d8'},{label:'DownKB',data:[],borderColor:'#90e0ef'}]}});
const c2 = new Chart(document.getElementById('c2'),{type:'bar',data:{labels:[],datasets:[{label:'Hits',data:[],backgroundColor:'#00b4d8'}]}});
const d=['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
const q=(u,o)=>fetch(u,o).then(r=>r.json());
async function refresh(){
const s=await q('/api/summary');mTotal.textContent=s.total_requests;mAllowed.textContent=s.allowed;mBlocked.textContent=s.blocked;mOpen.textContent=s.open_connections;
const ts=await q('/api/traffic/series');c1.data.labels=ts.map(x=>x.minute);c1.data.datasets[0].data=ts.map(x=>x.allowed);c1.data.datasets[1].data=ts.map(x=>x.blocked);c1.data.datasets[2].data=ts.map(x=>Math.round(x.up/102.4)/10);c1.data.datasets[3].data=ts.map(x=>Math.round(x.down/102.4)/10);c1.update();
const top=await q('/api/traffic/top-domains');c2.data.labels=top.map(x=>x.host);c2.data.datasets[0].data=top.map(x=>x.count);c2.update();
const cfg=await q('/api/config');rate.value=cfg.rate_limit;ids.checked=cfg.ids_enabled;dpi.checked=cfg.dpi_enabled;
sites.innerHTML=cfg.blocked_sites.map(x=>`<span class=chip>${x} <button onclick="delSite('${encodeURIComponent(x)}')">x</button></span>`).join('');
rules.innerHTML=cfg.time_rules.map(r=>`<tr><td>${r.keyword}</td><td>${String(r.start_hour).padStart(2,'0')}-${String(r.end_hour).padStart(2,'0')}</td><td>${r.days.map(x=>d[x]).join(',')}</td><td>${r.enabled?'ON':'OFF'}</td><td><button onclick="tg('${r.rule_id}')">toggle</button><button onclick="dr('${r.rule_id}')">del</button></td></tr>`).join('');
const al=await q('/api/alerts?limit=60');alerts.innerHTML=al.map(x=>`<tr><td>${x.time}</td><td>${x.category}</td><td>${x.client_ip}</td><td>${x.message}</td></tr>`).join('');
const st=await q('/api/stateful?limit=150');state.innerHTML=st.map(x=>`<tr><td>${x.connection_id}</td><td>${x.client_ip}</td><td>${x.target_host}:${x.target_port}</td><td>${x.protocol}</td><td>${x.state}</td><td>${x.up}</td><td>${x.down}</td><td>${x.last_seen_human}</td></tr>`).join('');
const lg=await q('/api/logs?limit=120');logs.innerHTML=lg.map(x=>`<tr><td>${x.time}</td><td>${x.client_ip}</td><td>${x.host}</td><td>${x.port}</td><td>${x.protocol}</td><td>${x.action}</td><td>${x.reason}</td><td>${x.up}</td><td>${x.down}</td></tr>`).join('');
}
async function delSite(s){await q('/api/block-sites/'+s,{method:'DELETE'});refresh()}
async function tg(id){await q('/api/time-rules/'+id+'/toggle',{method:'PATCH'});refresh()}
async function dr(id){await q('/api/time-rules/'+id,{method:'DELETE'});refresh()}
fSite.onsubmit=async e=>{e.preventDefault();await q('/api/block-sites',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({site:site.value})});site.value='';refresh()}
fSet.onsubmit=async e=>{e.preventDefault();await q('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rate_limit:Number(rate.value),ids_enabled:ids.checked,dpi_enabled:dpi.checked})});refresh()}
fRule.onsubmit=async e=>{e.preventDefault();const days=[...rd.options].filter(o=>o.selected).map(o=>Number(o.value));await q('/api/time-rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({keyword:rk.value,start_hour:Number(rs.value),end_hour:Number(re.value),days})});rk.value='';refresh()}
refresh();setInterval(refresh,3000);
</script></body></html>
"""


@app.get("/")
def dashboard():
    return render_template_string(HTML)


@app.get("/api/summary")
def api_summary():
    with state_lock:
        total = sum(action_counter.values())
        open_conn = sum(1 for x in connection_table.values() if x.state in {"NEW", "ESTABLISHED"})
        return jsonify(
            {
                "total_requests": total,
                "allowed": action_counter.get("ALLOWED", 0),
                "blocked": action_counter.get("BLOCKED", 0),
                "open_connections": open_conn,
                "alert_count": len(alerts),
                "rate_limit": RATE_LIMIT_PER_MINUTE,
                "ids_enabled": IDS_ENABLED,
                "dpi_enabled": DPI_ENABLED,
            }
        )


@app.get("/api/logs")
def api_logs():
    limit = max(1, min(int(request.args.get("limit", 100)), 500))
    with state_lock:
        return jsonify(list(logs)[:limit])


@app.get("/api/alerts")
def api_alerts():
    limit = max(1, min(int(request.args.get("limit", 100)), 500))
    with state_lock:
        return jsonify(list(alerts)[:limit])


@app.get("/api/stateful")
def api_stateful():
    limit = max(1, min(int(request.args.get("limit", 120)), 500))
    with state_lock:
        rows = sorted(connection_table.values(), key=lambda x: x.last_seen, reverse=True)[:limit]
        result = []
        for r in rows:
            d = asdict(r)
            d["last_seen_human"] = datetime.fromtimestamp(r.last_seen).strftime("%H:%M:%S")
            result.append(d)
        return jsonify(result)


@app.get("/api/traffic/top-domains")
def api_top_domains():
    with state_lock:
        return jsonify([{"host": h, "count": c} for h, c in host_counter.most_common(10)])


@app.get("/api/traffic/series")
def api_traffic_series():
    with state_lock:
        return jsonify(list(traffic_series))


@app.get("/api/config")
def api_config():
    with state_lock:
        return jsonify(
            {
                "rate_limit": RATE_LIMIT_PER_MINUTE,
                "ids_enabled": IDS_ENABLED,
                "dpi_enabled": DPI_ENABLED,
                "blocked_sites": sorted(BLOCKED_SITES),
                "time_rules": [asdict(x) for x in schedule_rules.values()],
            }
        )


@app.post("/api/block-sites")
def api_add_site():
    payload = request.get_json(silent=True) or {}
    site = normalize_domain(payload.get("site", ""))
    if not site:
        return jsonify({"error": "site is required"}), 400
    with state_lock:
        BLOCKED_SITES.add(site)
    return jsonify({"ok": True, "site": site})


@app.delete("/api/block-sites/<path:site>")
def api_del_site(site: str):
    with state_lock:
        BLOCKED_SITES.discard(normalize_domain(site))
    return jsonify({"ok": True})


@app.post("/api/settings")
def api_settings():
    global RATE_LIMIT_PER_MINUTE, IDS_ENABLED, DPI_ENABLED
    payload = request.get_json(silent=True) or {}
    rl = payload.get("rate_limit")
    if rl is not None:
        rl = int(rl)
        if rl < 10 or rl > 5000:
            return jsonify({"error": "rate_limit must be 10..5000"}), 400
        RATE_LIMIT_PER_MINUTE = rl
    if isinstance(payload.get("ids_enabled"), bool):
        IDS_ENABLED = payload["ids_enabled"]
    if isinstance(payload.get("dpi_enabled"), bool):
        DPI_ENABLED = payload["dpi_enabled"]
    return jsonify({"ok": True})


@app.post("/api/time-rules")
def api_add_time_rule():
    payload = request.get_json(silent=True) or {}
    keyword = normalize_domain(payload.get("keyword", ""))
    if not keyword:
        return jsonify({"error": "keyword is required"}), 400
    try:
        sh = int(payload.get("start_hour"))
        eh = int(payload.get("end_hour"))
    except Exception:  # noqa: BLE001
        return jsonify({"error": "hours must be numbers"}), 400
    if not (0 <= sh <= 23 and 0 <= eh <= 23):
        return jsonify({"error": "hours must be 0..23"}), 400
    days_raw = payload.get("days", [])
    if not isinstance(days_raw, list) or not days_raw:
        return jsonify({"error": "days must be non-empty list"}), 400
    days: List[int] = []
    for d in days_raw:
        di = int(d)
        if di < 0 or di > 6:
            return jsonify({"error": "days values must be 0..6"}), 400
        days.append(di)
    rule = TimeRule(str(uuid.uuid4())[:8], keyword, sh, eh, sorted(set(days)), True)
    with state_lock:
        schedule_rules[rule.rule_id] = rule
    return jsonify({"ok": True, "rule": asdict(rule)})


@app.patch("/api/time-rules/<rule_id>/toggle")
def api_toggle_rule(rule_id: str):
    with state_lock:
        r = schedule_rules.get(rule_id)
        if not r:
            return jsonify({"error": "rule not found"}), 404
        r.enabled = not r.enabled
        return jsonify({"ok": True, "rule": asdict(r)})


@app.delete("/api/time-rules/<rule_id>")
def api_del_rule(rule_id: str):
    with state_lock:
        if rule_id not in schedule_rules:
            return jsonify({"error": "rule not found"}), 404
        del schedule_rules[rule_id]
    return jsonify({"ok": True})


def start_dashboard() -> None:
    print(f"[dashboard] http://127.0.0.1:{DASHBOARD_PORT}")
    app.run(host="127.0.0.1", port=DASHBOARD_PORT, debug=False, use_reloader=False, threaded=True)


def seed_defaults() -> None:
    rule = TimeRule(str(uuid.uuid4())[:8], "social", 9, 17, [0, 1, 2, 3, 4], False)
    with state_lock:
        schedule_rules[rule.rule_id] = rule


if __name__ == "__main__":
    print("[init] Starting Stateful Proxy Firewall + SOC Dashboard")
    seed_defaults()
    threading.Thread(target=start_dashboard, daemon=True).start()
    start_proxy()
