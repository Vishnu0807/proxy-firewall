from flask import Flask, Response, jsonify, render_template, request


def create_app(firewall):
    app = Flask(__name__, template_folder="templates", static_folder="static")

    @app.get("/")
    def dashboard_home():
        return render_template("dashboard.html")

    @app.get("/dashboard.js")
    def dashboard_script():
        with open("dashboard_frontend.js", "r", encoding="utf-8") as file_handle:
            return Response(file_handle.read(), mimetype="application/javascript")

    @app.get("/api/summary")
    def api_summary():
        return jsonify(firewall.get_summary())

    @app.get("/api/logs")
    def api_logs():
        limit = max(1, min(int(request.args.get("limit", 100)), 500))
        return jsonify(firewall.get_logs(limit=limit))

    @app.get("/api/alerts")
    def api_alerts():
        limit = max(1, min(int(request.args.get("limit", 100)), 500))
        return jsonify(firewall.get_alerts(limit=limit))

    @app.get("/api/stateful")
    def api_stateful():
        limit = max(1, min(int(request.args.get("limit", 120)), 500))
        return jsonify(firewall.get_stateful_connections(limit=limit))

    @app.get("/api/traffic/top-domains")
    def api_top_domains():
        return jsonify(firewall.get_top_domains())

    @app.get("/api/traffic/series")
    def api_traffic_series():
        return jsonify(firewall.get_traffic_series())

    @app.get("/api/suspicious-ips")
    def api_suspicious_ips():
        limit = max(1, min(int(request.args.get("limit", 20)), 100))
        return jsonify(firewall.get_suspicious_ips(limit=limit))

    @app.get("/api/config")
    def api_config():
        return jsonify(firewall.get_config())

    @app.post("/api/settings")
    def api_settings():
        payload = request.get_json(silent=True) or {}
        try:
            return jsonify({"ok": True, "config": firewall.update_settings(payload)})
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.post("/api/blocked-ips")
    def api_add_blocked_ip():
        payload = request.get_json(silent=True) or {}
        try:
            ip = firewall.add_blocked_ip(payload.get("ip", "").strip())
            return jsonify({"ok": True, "ip": ip})
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.delete("/api/blocked-ips/<ip>")
    def api_delete_blocked_ip(ip: str):
        firewall.remove_blocked_ip(ip)
        return jsonify({"ok": True})

    @app.post("/api/block-sites")
    def api_add_blocked_site():
        payload = request.get_json(silent=True) or {}
        try:
            site = firewall.add_blocked_site(payload.get("site", ""))
            return jsonify({"ok": True, "site": site})
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.delete("/api/block-sites/<path:site>")
    def api_delete_blocked_site(site: str):
        firewall.remove_blocked_site(site)
        return jsonify({"ok": True})

    @app.post("/api/time-rules")
    def api_add_time_rule():
        payload = request.get_json(silent=True) or {}
        try:
            return jsonify({"ok": True, "rule": firewall.add_time_rule(payload)})
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.patch("/api/time-rules/<rule_id>/toggle")
    def api_toggle_time_rule(rule_id: str):
        try:
            return jsonify({"ok": True, "rule": firewall.toggle_time_rule(rule_id)})
        except KeyError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 404

    @app.delete("/api/time-rules/<rule_id>")
    def api_delete_time_rule(rule_id: str):
        try:
            firewall.delete_time_rule(rule_id)
            return jsonify({"ok": True})
        except KeyError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 404

    return app


def start_dashboard(firewall, host: str = "127.0.0.1", port: int = 5000) -> None:
    app = create_app(firewall)
    print(f"[dashboard] http://{host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
